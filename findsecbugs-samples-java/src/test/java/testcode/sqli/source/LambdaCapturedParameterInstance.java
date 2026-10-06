package testcode.sqli.source;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Optional;
import javax.servlet.http.HttpServletRequest;

public class LambdaCapturedParameterInstance {

    private Connection connection;

    public void delete(HttpServletRequest request, long id) {
        String tableName = request.getParameter("table");

        Optional.of(id).ifPresent(fooId -> {
            try {
                connection.prepareStatement("delete from " + tableName + " where fooId = ?").setLong(1, fooId);
            } catch (SQLException e) {
                throw new RuntimeException(e);
            }

            if (fooId > 0) {
                delete(request, fooId - 1);
            }
        });
    }
}
