package testcode.sqli.source;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class AnnotationElementValue {

    @Retention(RetentionPolicy.RUNTIME)
    public @interface Query {
        String value();
    }

    public ResultSet queryFromAnnotation(Statement statement, Query query) throws SQLException {
        return statement.executeQuery("select * from t where " + query.value());
    }

    public ResultSet queryFromName(Statement statement, String name) throws SQLException {
        return statement.executeQuery("select * from t where " + name);
    }
}
