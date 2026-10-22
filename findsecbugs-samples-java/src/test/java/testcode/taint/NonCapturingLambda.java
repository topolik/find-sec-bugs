package testcode.taint;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.function.Function;
import javax.servlet.http.HttpServletRequest;

public class NonCapturingLambda {

    private static final Function<String, String> TRIM = value -> value.trim();

    public void unsafe(HttpServletRequest request, Connection connection) throws SQLException {
        Function<String, String> function = value -> value.trim();

        connection.prepareStatement("select * from " + function.apply(request.getParameter("table")) + TRIM.apply(""));
    }
}
