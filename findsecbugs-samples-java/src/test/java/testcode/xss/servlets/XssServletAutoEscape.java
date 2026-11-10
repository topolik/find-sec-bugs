package testcode.xss.servlets;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class XssServletAutoEscape extends HttpServlet {

    public interface EntryModel {

        @AutoEscapeLike
        String getName();

        String getUrl();

        Entry escape();
    }

    public interface Entry extends EntryModel {
    }

    public void escapedAnnotated(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        Entry entry = load(req.getParameter("id")).escape();
        resp.getWriter().println(entry.getName());
    }

    public void escapedUnannotated(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        Entry entry = load(req.getParameter("id")).escape();
        resp.getWriter().println(entry.getUrl());
    }

    public void rawAnnotated(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        Entry entry = load(req.getParameter("id"));
        resp.getWriter().println(entry.getName());
    }

    private static native Entry load(String id);
}
