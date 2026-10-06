package testcode.sqli.source;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.function.Consumer;
import javax.servlet.http.HttpServletRequest;

public class LambdaCapturedParameterWithArgument {

    public void delete(HttpServletRequest request, Connection connection) {
        String tableName = request.getParameter("table");

        // The SQL depends on both a captured tainted value and a lambda argument.
        Consumer<String> delete = columnName -> {
            try {
                connection.prepareStatement(
                        "delete from " + tableName + " where " + columnName + " = ?");
            } catch (SQLException e) {
                throw new RuntimeException(e);
            }
        };
        delete.accept("fooId");
    }
}
