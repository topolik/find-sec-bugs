package testcode.sqli.source;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class ImmutableObjectArgument {

    public interface Registry {
        void put(Object value);
    }

    public ResultSet queryAfterStringRegistered(Statement statement, Registry registry, int id) throws SQLException {
        String value = String.valueOf(id);

        registry.put(value);

        return statement.executeQuery("select * from t where id = " + value);
    }

    public ResultSet queryAfterBuilderRegistered(Statement statement, Registry registry, int id) throws SQLException {
        StringBuilder sb = new StringBuilder();

        sb.append(id);

        registry.put(sb);

        return statement.executeQuery("select * from t where id = " + sb.toString());
    }
}
