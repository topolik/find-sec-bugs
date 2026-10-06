package testcode.sqli.source;

import java.sql.Connection;
import java.sql.SQLException;
import javax.servlet.http.HttpServletRequest;

public class LongArgumentCallee {

    private Connection connection;

    public void deleteFoo(HttpServletRequest request, long id) throws SQLException {
        delete(request.getParameter("table"), id);
    }

    private void delete(String tableName, long id) throws SQLException {
        connection.prepareStatement("delete from " + tableName + " where id = ?").setLong(1, id);
    }
}
