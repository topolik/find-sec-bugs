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
package com.h3xstream.findsecbugs.taintanalysis;

import com.h3xstream.findbugs.test.BaseDetectorTest;
import com.h3xstream.findbugs.test.EasyBugReporter;
import com.h3xstream.findsecbugs.FindSecBugsGlobalConfig;
import org.testng.annotations.AfterClass;
import org.testng.annotations.Test;

import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

/**
 * Tests a non-capturing lambda (invokedynamic without arguments) with the invokedynamic workaround enabled.
 */
public class NonCapturingLambdaTest extends BaseDetectorTest {

    @Test
    public void analyzeNonCapturingLambda() throws Exception {
        FindSecBugsGlobalConfig.getInstance().setWorkaroundVisitInvokeDynamic(true);

        String[] files = {
                getClassFilePath("testcode/taint/NonCapturingLambda")
        };

        EasyBugReporter reporter = spy(new SecurityReporter());
        analyze(files, reporter);

        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("SQL_INJECTION_JDBC")
                        .inClass("NonCapturingLambda").inMethod("unsafe")
                        .build()
        );
    }

    @AfterClass
    public void resetWorkaround() {
        FindSecBugsGlobalConfig.getInstance().setWorkaroundVisitInvokeDynamic(false);
    }
}
