/**
 * Find Security Bugs
 * Copyright (c) Philippe Arteau, All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.
 */
package testcode.taint;

import org.hibernate.SessionFactory;

import javax.servlet.http.HttpServletRequest;

/**
 * Static field taint must not depend on the order the methods are analyzed in. The writers and the
 * readers are paired in several shapes, some variants only differ in the method names.
 */
public class StaticFieldOrder {
    private HttpServletRequest request;
    private SessionFactory sessionFactory;

    private static String writerCallsReader1;
    private static String writerCallsReader2;
    private static String writerCallsReader3;
    private static String writerWithArgReader;
    private static String independent1;
    private static String independent2;
    private static String independent3;
    private static String readerCallsWriter1;
    private static String readerCallsWriter2;
    private static String readerCallsWriter3;
    private static String safe1;
    private static String safe2;
    private static String safe3;
    private static String lambda;
    private static String recursive;

    public void writerCallsReaderWriter1() {
        writerCallsReader1 = request.getParameter("test");
        writerCallsReaderReader1();
    }

    public void writerCallsReaderReader1() {
        sessionFactory.openSession().createQuery("FROM comment WHERE userId like " + writerCallsReader1);
    }

    public void aWriter2() {
        writerCallsReader2 = request.getParameter("test");
        zReader2();
    }

    public void zReader2() {
        sessionFactory.openSession().createQuery("FROM comment WHERE userId like " + writerCallsReader2);
    }

    public void zWriter3() {
        writerCallsReader3 = request.getParameter("test");
        aReader3();
    }

    public void aReader3() {
        sessionFactory.openSession().createQuery("FROM comment WHERE userId like " + writerCallsReader3);
    }

    public void writerWithArgReaderWriter() {
        writerWithArgReader = request.getParameter("test");
        writerWithArgReaderReader("constant");
    }

    public void writerWithArgReaderReader(String value) {
        sessionFactory.openSession().createQuery(value + writerWithArgReader);
    }

    public void independentWriter1() {
        independent1 = request.getParameter("test");
    }

    public void independentReader1() {
        sessionFactory.openSession().createQuery("FROM comment WHERE userId like " + independent1);
    }

    public void aIndependentWriter2() {
        independent2 = request.getParameter("test");
    }

    public void zIndependentReader2() {
        sessionFactory.openSession().createQuery("FROM comment WHERE userId like " + independent2);
    }

    public void zIndependentWriter3() {
        independent3 = request.getParameter("test");
    }

    public void aIndependentReader3() {
        sessionFactory.openSession().createQuery("FROM comment WHERE userId like " + independent3);
    }

    public void readerCallsWriterReader1() {
        readerCallsWriterWriter1();
        sessionFactory.openSession().createQuery("FROM comment WHERE userId like " + readerCallsWriter1);
    }

    public void readerCallsWriterWriter1() {
        readerCallsWriter1 = request.getParameter("test");
    }

    public void aReaderCallsWriter2() {
        zWriterCalledByReader2();
        sessionFactory.openSession().createQuery("FROM comment WHERE userId like " + readerCallsWriter2);
    }

    public void zWriterCalledByReader2() {
        readerCallsWriter2 = request.getParameter("test");
    }

    public void zReaderCallsWriter3() {
        aWriterCalledByReader3();
        sessionFactory.openSession().createQuery("FROM comment WHERE userId like " + readerCallsWriter3);
    }

    public void aWriterCalledByReader3() {
        readerCallsWriter3 = request.getParameter("test");
    }

    public void safeWriter1() {
        safe1 = "constant";
    }

    public void safeReader1() {
        sessionFactory.openSession().createQuery("FROM comment WHERE userId like " + safe1);
    }

    public void aSafeWriter2() {
        safe2 = "constant";
    }

    public void zSafeReader2() {
        sessionFactory.openSession().createQuery("FROM comment WHERE userId like " + safe2);
    }

    public void zSafeWriter3() {
        safe3 = "constant";
    }

    public void aSafeReader3() {
        sessionFactory.openSession().createQuery("FROM comment WHERE userId like " + safe3);
    }

    public void lambdaWriter() {
        Runnable runnable = () -> lambda = request.getParameter("test");
        runnable.run();
    }

    public void lambdaReader() {
        sessionFactory.openSession().createQuery("FROM comment WHERE userId like " + lambda);
    }

    public void recursiveWriter(int depth) {
        if (depth > 0) {
            recursiveReader(depth - 1);
        }
        recursive = request.getParameter("test");
    }

    public void recursiveReader(int depth) {
        sessionFactory.openSession().createQuery("FROM comment WHERE userId like " + recursive);
        recursiveWriter(depth);
    }
}
