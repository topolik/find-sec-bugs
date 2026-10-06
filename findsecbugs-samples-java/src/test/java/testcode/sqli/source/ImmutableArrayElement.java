package testcode.sqli.source;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Objects;

public class ImmutableArrayElement {

    public void count(Connection connection, String selectedTableName, boolean distinct) throws SQLException {
        for (String tableName : new String[] {"Foo", "Bar"}) {
            boolean selected = Objects.equals(selectedTableName, tableName);
            String prefix = distinct ? "select distinct count(*) from " : "select count(*) from ";
            try {
                connection.prepareStatement(prefix + tableName + (selected ? " where 1 = 1" : ""));
            } finally {
                connection.prepareStatement("select * from " + tableName);
            }
        }
    }
}
