package testcode.taint;

import org.hibernate.SessionFactory;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Instance methods hold this in slot 0 and static methods do not, so the parameter annotations must be read from the
 * right slot in both.
 */
public class ParameterSlotTaintedByAnnotationEndpoint {

    private static SessionFactory sessionFactory;

    public void instanceTaintedFirst(@RequestParam("user") String user, String input) {
        sessionFactory.openSession().createQuery("FROM comment WHERE user='" + user + "'"); //High
    }

    public void instanceUntaintedSecond(@RequestParam("user") String user, String input) {
        sessionFactory.openSession().createQuery("FROM comment WHERE user='" + input + "'"); //Medium
    }

    public static void staticTaintedFirst(@RequestParam("user") String user, String input) {
        sessionFactory.openSession().createQuery("FROM comment WHERE user='" + user + "'"); //High
    }

    public static void staticUntaintedSecond(@RequestParam("user") String user, String input) {
        sessionFactory.openSession().createQuery("FROM comment WHERE user='" + input + "'"); //Medium
    }
}
