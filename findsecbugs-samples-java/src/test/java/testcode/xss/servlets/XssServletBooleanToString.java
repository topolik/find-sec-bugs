package testcode.xss.servlets;

import java.io.IOException;
import java.util.function.BooleanSupplier;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class XssServletBooleanToString extends HttpServlet {

    private BooleanSupplier enabled;

    @Override
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.getWriter().print(Boolean.toString(enabled.getAsBoolean()));
    }
}
