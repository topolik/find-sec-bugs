package testcode.taint;

import org.hibernate.SessionFactory;

import javax.servlet.http.HttpServletRequest;

/**
 * @author Tomas Polesovsky
 */
public class ClassContextTaintPropagation {

    private HttpServletRequest request;
    private SessionFactory sessionFactory;

    public void safeSetField(){
        classA classA = new classA();

        classA.s = "safe";

        sessionFactory.openSession().createQuery("FROM comment WHERE userId="+classA.s);
    }

    public void safeFieldSetter(){
        classA classA = new classA();

        classA.setS("safe");

        sessionFactory.openSession().createQuery("FROM comment WHERE userId="+classA.s);
    }


    public void safeConstructor(){
        classA classA = new classA("safe");

        sessionFactory.openSession().createQuery("FROM comment WHERE userId=" + classA.s);
    }


    public void safeConcatField(){
        String s1 = returnsSafe();
        classA classA = new classA(s1);
        String s = classA.toString();
        sessionFactory.openSession().createQuery("FROM comment WHERE userId=" + s);
    }

    private String returnsSafe() {
        return "safe";
    }

    public void safeNestedClasses(){
        classA ca = new classA();

        ca.s = "";

        classB cb = new classB();

        cb.cA = ca;

        sessionFactory.openSession().createQuery("FROM comment WHERE userId="+cb.cA.s);
    }

    private classB cb1;

    public void unknownUninitializedCrossContextField(){
        sessionFactory.openSession().createQuery("FROM comment WHERE userId=" + cb1.cA.s);
    }

    public void safeLocallyInitializedCrossContextField(){
        cb1 = new classB();

        cb1.cA = new classA("safe");

        sessionFactory.openSession().createQuery("FROM comment WHERE userId=" + cb1.cA.s);
    }

    private classB cb2 = new classB(){{
        this.cA = new classA("safe");
    }};

    public void safeLocallyInitializedCrossContextField2() {
        cb2 = new classB(){{
            this.cA = new classA("safe");
        }};

        sessionFactory.openSession().createQuery("FROM comment WHERE userId=" + cb2.toString());
    }

    public void unknownLocalVarWithSafeCallOnly(){
        sessionFactory.openSession().createQuery("FROM comment WHERE userId=" + cb2.cA.s);
    }

    public static void safeStaticDefaultInitializedField() {
        new ClassContextTaintPropagation().unknownLocalVarWithSafeCallOnly();
    }

    public void unknownLocalVarWithTaintedCall(){
        sessionFactory.openSession().createQuery("FROM comment WHERE userId=" + cb2.cA.s);
    }

    public void taintedLocallyInitializedCrossContextField() {
        cb2 = new classB(request.getParameter("tainted"));

        unknownLocalVarWithTaintedCall();
    }

    public void unknownLocalVarWithTaintedCall1(){
        sessionFactory.openSession().createQuery("FROM comment WHERE userId=" + cb2.cA.s);
    }

    public static void safeStaticLocallyInitializedCrossContextField() {
        ClassContextTaintPropagation someClass = new ClassContextTaintPropagation();

        someClass.cb2 = new classB(someClass.request.getParameter("tainted"));

        someClass.unknownLocalVarWithTaintedCall1();
    }

    public void unknownLocalVarWithTaintedCall2(){
        sessionFactory.openSession().createQuery("FROM comment WHERE userId=" + cb2.cA.s);
    }

    public static void taintedStaticLocallyInitializedLocalVarWithCustomInitBlock() {
        ClassContextTaintPropagation someClass = new ClassContextTaintPropagation();
        final String tainted = someClass.request.getParameter("tainted");

        someClass.cb2 = new classB(){{
            this.cA = new classA(tainted);
        }};

        someClass.unknownLocalVarWithTaintedCall2();
    }

    public void safeAnonymousClass() {
        classB cb2 = new classB(){{
            this.cA = new classA("safe");
        }};

        sessionFactory.openSession().createQuery("FROM comment WHERE userId="+cb2.cA.toString());
    }

    public void taintedAnonymousClass() {
        classB cb2 = new classB(){{
            this.cA = new classA(request.getParameter("tainted"));
        }};

        sessionFactory.openSession().createQuery("FROM comment WHERE userId="+cb2.cA.toString());
    }

    public void simplyUnknown(String s){
        classA classA = new classA(s);

        sessionFactory.openSession().createQuery("FROM comment WHERE userId="+classA.s);
    }

    static class classA {
        public classA(){}

        public classA(String s) {
            this.s = s;
        }

        public void setS(String s) {
            this.s = s;
        }

        protected String s;

        @Override
        public String toString() {
            return "classA{" +
                    "s='" + s + '\'' +
                    '}';
        }

    }

    static class classB {
        public classB() {
        }

        public classB(String s) {
            cA = new classA(s);
        }

        protected classA cA;

        @Override
        public String toString() {
            return "classB{" +
                    "cA=" + cA +
                    '}';
        }
    }

}
