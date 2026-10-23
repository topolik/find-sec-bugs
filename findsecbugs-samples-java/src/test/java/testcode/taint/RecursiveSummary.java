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
 * The summaries of mutually recursive methods depend on each other, the first analyzed one does not
 * know the summary of the other yet.
 */
public class RecursiveSummary {
    private HttpServletRequest request;
    private SessionFactory sessionFactory;

    public void query() {
        first(0);
        sessionFactory.openSession().createQuery(second("FROM comment WHERE userId like ", 1));
    }

    private String first(int depth) {
        if (depth > 0) {
            return second("constant", depth - 1);
        }
        return request.getParameter("test");
    }

    private String second(String value, int depth) {
        return value + first(depth);
    }
}
