package testcode.taint;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * Two locals that refer to the same object on every path are must-aliases, so a
 * mutation through one of them changes what the other one sees. An alias that
 * holds on one path only, or a local reassigned to another object, is not one.
 */
public class MustAlias extends HttpServlet {

    private Consumer<List<String>> consumer;
    private List<String> names = new ArrayList<>();

    protected void mutatedListAlias(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        List<String> labels = new ArrayList<>();
        List<String> alias = labels;

        alias.add(req.getParameter("label"));

        resp.getWriter().print(labels.get(0));
    }

    protected void mutatedAliasOfAlias(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        List<String> labels = new ArrayList<>();
        List<String> alias = labels;
        List<String> aliasOfAlias = alias;

        aliasOfAlias.add(req.getParameter("label"));

        resp.getWriter().print(labels.get(0));
    }

    protected void mutatedBuilderAlias(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        StringBuilder sb = new StringBuilder();
        StringBuilder alias = sb;

        alias.append(req.getParameter("label"));

        resp.getWriter().print(sb.toString());
    }

    protected void mutatedBuilderAliasThroughChain(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {

        StringBuilder sb = new StringBuilder();
        StringBuilder alias = sb;

        alias.append("label: ").append(req.getParameter("label"));

        resp.getWriter().print(sb.toString());
    }

    @SuppressWarnings("unchecked")
    protected void mutatedCastAlias(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        Object labels = new ArrayList<String>();
        List<String> alias = (List<String>) labels;

        alias.add(req.getParameter("label"));

        resp.getWriter().print(((List<String>) labels).get(0));
    }

    protected void mutatedAliasInLoop(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        List<String> labels = new ArrayList<>();
        List<String> alias = labels;

        for (String label : req.getParameterValues("label")) {
            alias.add(label);
        }

        resp.getWriter().print(labels.get(0));
    }

    protected void aliasPassedToUnknownCode(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        List<String> labels = new ArrayList<>();
        List<String> alias = labels;

        consumer.accept(alias);

        resp.getWriter().print(labels.get(0));
    }

    protected void mutatedFieldLoadedTwice(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        List<String> alias = names;
        List<String> labels = names;

        alias.add(req.getParameter("label"));

        resp.getWriter().print(labels.get(0));
    }

    protected void mutatedParameterAlias(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        List<String> labels = new ArrayList<>();

        addThroughAlias(labels, req.getParameter("label"));

        resp.getWriter().print(labels.get(0));
    }

    /**
     * Known false negative, the locals refer to the same object on one path only
     */
    protected void mutatedAliasOnOnePath(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        List<String> labels = new ArrayList<>();
        List<String> alias = req.getParameter("all") != null ? labels : new ArrayList<>();

        alias.add(req.getParameter("label"));

        resp.getWriter().print(labels.get(0));
    }

    protected void mutatedReassignedAlias(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        List<String> labels = new ArrayList<>();
        List<String> alias = labels;

        alias = new ArrayList<>();

        alias.add(req.getParameter("label"));

        resp.getWriter().print(labels.get(0));
    }

    protected void mutatedReassignedParameter(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        List<String> labels = new ArrayList<>();

        addToReassigned(labels, req.getParameter("label"));

        resp.getWriter().print(labels.get(0));
    }

    private void addThroughAlias(List<String> labels, String label) {
        List<String> alias = labels;

        alias.add(label);
    }

    private void addToReassigned(List<String> labels, String label) {
        labels = new ArrayList<>();

        labels.add(label);
    }
}
