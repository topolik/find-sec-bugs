package testcode.sqli.source;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class SafeElementArray {

    public interface Query {
        Long[] getIds();

        String[] getNames();
    }

    public ResultSet queryIds(Statement statement, Query query) throws SQLException {
        return statement.executeQuery("select * from t where id = " + String.valueOf(query.getIds()[0]));
    }

    public ResultSet queryNames(Statement statement, Query query) throws SQLException {
        return statement.executeQuery("select * from t where name = " + query.getNames()[0]);
    }
}
