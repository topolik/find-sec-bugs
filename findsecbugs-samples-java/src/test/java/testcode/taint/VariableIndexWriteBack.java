package testcode.taint;

import org.owasp.encoder.Encode;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * A value loaded from a local remembers the local's index, so a mutating call on
 * the value writes its new taint back to that local. The value of a method call
 * is not stored in any local, so it must not keep the index of an argument it was
 * created from. It does not keep the index of the receiver it shares data with
 * either, so mutating a map value or entry is not written back to the map.
 */
public class VariableIndexWriteBack extends HttpServlet {

    private Consumer<List<String>> consumer;

    private LabelSource labelSource;

    protected void mutatedLocal(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        List<String> labels = new ArrayList<>();

        labels.add(req.getParameter("label"));

        resp.getWriter().print(labels.get(0));
    }

    protected void mutatedLocalThroughChain(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        StringBuilder sb = new StringBuilder();

        sb.append("label: ").append(req.getParameter("label"));

        resp.getWriter().print(sb.toString());
    }

    protected void mutatedLocalThroughChainAfterUnknownValue(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {

        StringBuilder sb = new StringBuilder();

        sb.append(labelSource.label()).append(req.getParameter("label"));

        resp.getWriter().print(sb.toString());
    }

    protected void mutatedCopy(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        List<String> labels = new ArrayList<>();
        List<String> copy = new ArrayList<>(labels);

        copy.add(req.getParameter("label"));

        resp.getWriter().print(copy.get(0));
    }

    protected void mutatedMapValue(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        Map<String, List<String>> labels = new HashMap<>();

        labels.get("a").add(req.getParameter("label"));

        resp.getWriter().print(labels.get("a"));
    }

    protected void mutatedMapEntry(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        Map<String, String> labels = new HashMap<>();

        labels.entrySet().iterator().next().setValue(req.getParameter("label"));

        resp.getWriter().print(labels.get("a"));
    }

    protected void sourceOfMutatedCopy(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        List<String> labels = new ArrayList<>();

        labels.add("safe");

        new ArrayList<>(labels).add(req.getParameter("label"));

        resp.getWriter().print(labels.get(0));
    }

    protected void sourceOfStoredMutatedCopy(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String label = Encode.forHtml(req.getParameter("label"));
        List<String> copy = new ArrayList<>(Collections.singletonList(label));

        copy.add(req.getParameter("other"));

        resp.getWriter().print(label);
    }

    protected void argumentOfTransferResultPassedToUnknownCode(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {

        String label = Encode.forHtml(req.getParameter("label"));

        consumer.accept(Collections.singletonList(label));

        resp.getWriter().print(label);
    }

    private interface LabelSource {

        String label();
    }
}
