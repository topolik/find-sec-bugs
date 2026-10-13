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
package com.h3xstream.findsecbugs.injection.sql;

import com.h3xstream.findbugs.test.BaseDetectorTest;
import com.h3xstream.findbugs.test.EasyBugReporter;
import com.h3xstream.findsecbugs.FindSecBugsGlobalConfig;
import org.testng.annotations.Test;

import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Test for Statement.enquoteLiteral, enquoteIdentifier, and enquoteNCharLiteral methods
 * Issue #721: These methods should be marked as SQL_INJECTION_SAFE
 */
public class StatementEnquoteMethodsTest extends BaseDetectorTest {

    @Test
    public void detectSafeEnquoteLiteral() throws Exception {
        // Enable the Java 9+ invokedynamic string concatenation workaround
        FindSecBugsGlobalConfig.getInstance().setWorkaroundVisitInvokeDynamic(true);

        // Locate test code
        String[] files = {
                getClassFilePath("testcode/sqli/StatementEnquoteMethods")
        };

        // Run the analysis
        EasyBugReporter reporter = spy(new SecurityReporter());
        analyze(files, reporter);

        // enquoteLiteral should NOT report bugs (it's safe)
        verify(reporter, never()).doReportBug(
                bugDefinition()
                        .bugType("SQL_INJECTION_JDBC")
                        .inClass("StatementEnquoteMethods")
                        .inMethod("safeLiteralUsage")
                        .build()
        );
    }

    @Test
    public void detectSafeEnquoteIdentifier() throws Exception {
        // Enable the Java 9+ invokedynamic string concatenation workaround
        FindSecBugsGlobalConfig.getInstance().setWorkaroundVisitInvokeDynamic(true);

        // Locate test code
        String[] files = {
                getClassFilePath("testcode/sqli/StatementEnquoteMethods")
        };

        // Run the analysis
        EasyBugReporter reporter = spy(new SecurityReporter());
        analyze(files, reporter);

        // enquoteIdentifier should NOT report bugs (it's safe)
        verify(reporter, never()).doReportBug(
                bugDefinition()
                        .bugType("SQL_INJECTION_JDBC")
                        .inClass("StatementEnquoteMethods")
                        .inMethod("safeIdentifierUsage")
                        .build()
        );

        verify(reporter, never()).doReportBug(
                bugDefinition()
                        .bugType("SQL_INJECTION_JDBC")
                        .inClass("StatementEnquoteMethods")
                        .inMethod("safeIdentifierUsageNoQuote")
                        .build()
        );
    }

    @Test
    public void detectSafeEnquoteNCharLiteral() throws Exception {
        // Enable the Java 9+ invokedynamic string concatenation workaround
        FindSecBugsGlobalConfig.getInstance().setWorkaroundVisitInvokeDynamic(true);

        // Locate test code
        String[] files = {
                getClassFilePath("testcode/sqli/StatementEnquoteMethods")
        };

        // Run the analysis
        EasyBugReporter reporter = spy(new SecurityReporter());
        analyze(files, reporter);

        // enquoteNCharLiteral should NOT report bugs (it's safe)
        verify(reporter, never()).doReportBug(
                bugDefinition()
                        .bugType("SQL_INJECTION_JDBC")
                        .inClass("StatementEnquoteMethods")
                        .inMethod("safeNCharLiteralUsage")
                        .build()
        );
    }

    @Test
    public void detectSafeMultipleEnquoteMethods() throws Exception {
        // Enable the Java 9+ invokedynamic string concatenation workaround
        FindSecBugsGlobalConfig.getInstance().setWorkaroundVisitInvokeDynamic(true);

        // Locate test code
        String[] files = {
                getClassFilePath("testcode/sqli/StatementEnquoteMethods")
        };

        // Run the analysis
        EasyBugReporter reporter = spy(new SecurityReporter());
        analyze(files, reporter);

        // Multiple enquote methods used together should NOT report bugs
        verify(reporter, never()).doReportBug(
                bugDefinition()
                        .bugType("SQL_INJECTION_JDBC")
                        .inClass("StatementEnquoteMethods")
                        .inMethod("multipleEnquoteUsage")
                        .build()
        );
    }

    @Test
    public void detectUnsafeDirectConcatenation() throws Exception {
        // Enable the Java 9+ invokedynamic string concatenation workaround
        FindSecBugsGlobalConfig.getInstance().setWorkaroundVisitInvokeDynamic(true);

        // Locate test code
        String[] files = {
                getClassFilePath("testcode/sqli/StatementEnquoteMethods")
        };

        // Run the analysis
        EasyBugReporter reporter = spy(new SecurityReporter());
        analyze(files, reporter);

        // Direct concatenation of unsanitized input should still be reported
        verify(reporter, times(1)).doReportBug(
                bugDefinition()
                        .bugType("SQL_INJECTION_JDBC")
                        .inClass("StatementEnquoteMethods")
                        .inMethod("unsafeDirectConcatenation")
                        .build()
        );
    }
}