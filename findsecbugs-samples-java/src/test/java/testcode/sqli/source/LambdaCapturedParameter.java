package testcode.sqli.source;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.function.Consumer;
import javax.servlet.http.HttpServletRequest;

public class LambdaCapturedParameter {

    public void deleteFoo(HttpServletRequest request, long id) {
        delete(request.getParameter("table"), "fooId", id);
    }

    private void delete(String tableName, String columnName, long id) {
        run(connection -> {
            try {
                connection.prepareStatement(
                    "delete from " + tableName + " where " + columnName + " = ?").setLong(1, id);
            } catch (SQLException e) {
                throw new RuntimeException(e);
            }
        });
    }

    private void run(Consumer<Connection> consumer) {
        consumer.accept(null);
    }
}
