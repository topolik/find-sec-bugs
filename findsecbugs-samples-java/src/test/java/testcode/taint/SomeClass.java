package testcode.taint;

import org.hibernate.SessionFactory;

import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * @author Tomas Polesovsky
 */
public class SomeClass extends Exception{

    private HttpServletRequest request;
    private SessionFactory sessionFactory;

    public void safe(){
        classA classA = new classA();

        classA.s = "safe";

        sessionFactory.openSession().createQuery("FROM comment WHERE userId="+classA.s);
    }


    public void safe1(){
        classA classA = new classA("safe");

        sessionFactory.openSession().createQuery("FROM comment WHERE userId=" + classA.s);
    }


    public void safe2(){
        String s1 = returnsSafe();
        classA classA = new classA(s1);
        String s = classA.toString();
        sessionFactory.openSession().createQuery("FROM comment WHERE userId=" + s);
    }

    private String returnsSafe() {
        return "safe";
    }

    public void safe3(){
        classA ca = new classA();

        ca.s = "";

        classB cb = new classB();

        cb.cA = ca;

        sessionFactory.openSession().createQuery("FROM comment WHERE userId="+cb.cA.s);
    }

    private classB cb1;

    public void safe4(){
        cb1 = new classB();

        cb1.cA = new classA("safe");

        sessionFactory.openSession().createQuery("FROM comment WHERE userId="+cb1.cA.s);
    }

    private classB cb2 = new classB(){{
        this.cA = new classA("safe");
    }};

    public void safe5(){
        sessionFactory.openSession().createQuery("FROM comment WHERE userId="+cb1.cA.s);
    }

    public void unknown(String s){
        classA classA = new classA(s);

        sessionFactory.openSession().createQuery("FROM comment WHERE userId="+classA.s);
    }


    class classA {
        public classA(){}

        public classA(String s) {
            this.s = s;
        }

        private String s;

        @Override
        public String toString() {
            return "classA{" +
                    "s='" + s + '\'' +
                    '}';
        }

    }

    class classB {
        protected classA cA;
    }

}
