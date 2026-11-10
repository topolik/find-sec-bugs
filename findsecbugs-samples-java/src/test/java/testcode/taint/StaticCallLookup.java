package testcode.taint;

import org.owasp.encoder.Encode;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * The first argument of a static call is not its receiver, so the class of the
 * argument must not be used to look up the taint config or the sink.
 */
public class StaticCallLookup extends HttpServlet {

    protected void sanitized(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String label = new String(req.getParameter("label"));

        resp.getWriter().print(Encode.forHtml(label));
    }

    protected void transferred(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        StringBuilder sb = new StringBuilder(req.getParameter("label"));

        resp.getWriter().print(String.valueOf(sb));
    }

    protected Path derivedSink(HttpServletRequest req) {
        String name = new String(req.getParameter("name"));

        return resolve(name);
    }

    private static Path resolve(String name) {
        return Paths.get(name);
    }
}
