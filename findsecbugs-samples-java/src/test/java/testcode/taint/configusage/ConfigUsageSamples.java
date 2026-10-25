package testcode.taint.configusage;

import java.util.List;
import javax.servlet.http.HttpServletRequest;

public class ConfigUsageSamples {

    public static String neverCalled() {
        return "never";
    }

    public String constant() {
        return "constant";
    }

    public static Integer number(String value) {
        return value.length();
    }

    public static Integer count(List<String> values) {
        return values.size();
    }

    public static String echo(String value) {
        return value;
    }

    public static String parameter(HttpServletRequest request) {
        return request.getParameter("p");
    }

    public void use(HttpServletRequest request, List<String> values, ConfigUsageService service,
            ConfigUsageChild child) {
        String value = request.getHeader("h");
        new ConfigUsageSamples().constant();
        number(value);
        count(values);
        echo(value);
        parameter(request);
        request.getQueryString();
        service.getName();
        service.lookup("safe");
        child.label();
    }
}
