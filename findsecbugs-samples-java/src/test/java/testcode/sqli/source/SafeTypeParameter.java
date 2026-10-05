package testcode.sqli.source;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Date;

public class SafeTypeParameter {

    public ResultSet queryByCount(Statement statement, Integer count) throws SQLException {
        return statement.executeQuery("select * from t where count = " + count);
    }

    public ResultSet queryByDate(Statement statement, Date date) throws SQLException {
        return statement.executeQuery("select * from t where date = '" + date + "'");
    }

    public ResultSet queryById(Statement statement, Long id) throws SQLException {
        return statement.executeQuery("select * from t where id = " + id);
    }

    public ResultSet queryByInitial(Statement statement, char initial) throws SQLException {
        return statement.executeQuery("select * from t where initial = '" + initial + "'");
    }

    public ResultSet queryByName(Statement statement, String name) throws SQLException {
        return statement.executeQuery("select * from t where name = " + name);
    }
}
