package testcode.taint;

import org.hibernate.SessionFactory;

import javax.servlet.http.HttpServletRequest;

/**
 * @author Tomas Polesovsky
 */
public class SomeClass {
    private HttpServletRequest request;
    private SessionFactory sessionFactory;

    public void tainted(){
        StringBuffer sb = new StringBuffer();

        apppendRequestParameter(sb, "param", 0, 0);

        sessionFactory.openSession().createQuery("FROM comment WHERE userId="+sb.toString());
    }

    public void safe(){
        StringBuffer sb = new StringBuffer();

        appendString(sb, "param", 0, 0);

        sessionFactory.openSession().createQuery("FROM comment WHERE userId="+sb.toString());
    }

    public boolean apppendRequestParameter(StringBuffer sb, String name, double defaultValue, float f) {
        String parameter = request.getParameter(name);

        if (parameter != null) {
            sb.append(parameter);

            return true;
        }
        else {
            sb.append(defaultValue);

            return false;
        }
    }

    public boolean appendString(StringBuffer sb, String str, double dbl, float f) {
        sb.append(str);
        sb.append(dbl);

        return true;
    }
}
