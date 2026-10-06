package testcode.xss.servlets;

import org.springframework.web.util.HtmlUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class XssServletPartialEscape extends HttpServlet {

    public void escapedConcat(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.getWriter().println(meta("property", req.getParameter("x")));
    }

    public void escapedJoin(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.getWriter().println(metaJoin("property", req.getParameter("x")));
    }

    public void rawConcat(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.getWriter().println(meta(req.getParameter("n"), "v"));
    }

    public void rawJoin(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.getWriter().println(metaJoin(req.getParameter("n"), "v"));
    }

    private String meta(String name, String value) {
        return "<meta " + name + "=\"" + HtmlUtils.htmlEscape(value) + "\">";
    }

    private String metaJoin(String name, String value) {
        return String.join("", "<meta ", name, "=\"", HtmlUtils.htmlEscape(value), "\">");
    }
}
