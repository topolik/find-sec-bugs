package testcode.sqli.source;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.function.Consumer;

public class LambdaCapturedConstant {

    public void deleteFoo(long id) {
        delete("Foo", "fooId", id);
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
