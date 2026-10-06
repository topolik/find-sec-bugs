package testcode.xss.servlets;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class XssServletStrip extends HttpServlet {

    private int count;

    @Override
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String value = " " + String.valueOf(count);

        resp.getWriter().print(value.strip());
        resp.getWriter().print(value.stripLeading());
        resp.getWriter().print(value.stripTrailing());
    }
}
