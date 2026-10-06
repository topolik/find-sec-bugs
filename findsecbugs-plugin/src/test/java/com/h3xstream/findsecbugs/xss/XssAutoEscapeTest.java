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
package com.h3xstream.findsecbugs.xss;

import com.h3xstream.findbugs.test.BaseDetectorTest;
import com.h3xstream.findbugs.test.EasyBugReporter;
import com.h3xstream.findsecbugs.FindSecBugsGlobalConfig;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.File;

import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

public class XssAutoEscapeTest extends BaseDetectorTest {

    @BeforeClass
    public void setUpConfig() throws Exception {
        File configFile = new File(getClass().getResource("/com/h3xstream/findsecbugs/xss/AutoEscapeConfig.txt").toURI());
        FindSecBugsGlobalConfig.getInstance().setCustomConfigFile(configFile.getCanonicalPath());
    }

    @AfterClass
    public void tearDownConfig() {
        FindSecBugsGlobalConfig.getInstance().setCustomConfigFile("");
    }

    @Test
    public void receiverTaintThroughAnnotatedGetter() throws Exception {
        String[] files = {
                getClassFilePath("testcode/xss/servlets/XssServletAutoEscape"),
                getClassFilePath("testcode/xss/servlets/XssServletAutoEscape$Entry"),
                getClassFilePath("testcode/xss/servlets/XssServletAutoEscape$EntryModel"),
                getClassFilePath("testcode/xss/servlets/AutoEscapeLike")
        };

        EasyBugReporter reporter = spy(new SecurityReporter());
        analyze(files, reporter);

        for (String priority : new String[] {"High", "Medium", "Low"}) {
            verify(reporter, never()).doReportBug(
                    bugDefinition()
                            .bugType("XSS_SERVLET")
                            .inClass("XssServletAutoEscape")
                            .inMethod("escapedAnnotated")
                            .withPriority(priority)
                            .build()
            );
        }

        // an unannotated getter keeps the default UNKNOWN taint
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("XSS_SERVLET")
                        .inClass("XssServletAutoEscape")
                        .inMethod("escapedUnannotated")
                        .build()
        );

        // the annotated getter transfers the tainted, unescaped receiver
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("XSS_SERVLET")
                        .inClass("XssServletAutoEscape")
                        .inMethod("rawAnnotated")
                        .withPriority("High")
                        .build()
        );
    }
}
