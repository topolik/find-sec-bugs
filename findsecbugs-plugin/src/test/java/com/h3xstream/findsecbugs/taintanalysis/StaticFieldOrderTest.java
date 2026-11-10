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
import java.util.ArrayList;
import java.util.List;
import org.testng.annotations.Test;

import static org.testng.Assert.assertTrue;

import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

public class StaticFieldOrderTest extends BaseDetectorTest {

    private static final String[] TAINTED_READERS = {
            "writerCallsReaderReader1", "zReader2", "aReader3", "writerWithArgReaderReader",
            "independentReader1", "zIndependentReader2", "aIndependentReader3", "readerCallsWriterReader1",
            "aReaderCallsWriter2", "zReaderCallsWriter3", "lambdaReader", "recursiveReader"
    };

    private static final String[] SAFE_READERS = {
            "safeReader1", "zSafeReader2", "aSafeReader3"
    };

    @Test
    public void staticFieldTaintDoesNotDependOnMethodOrder() throws Exception {
        String[] files = {
                getClassFilePath("testcode/taint/StaticFieldOrder")
        };

        EasyBugReporter reporter = spy(new SecurityReporter());
        analyze(files, reporter);

        List<String> failures = new ArrayList<String>();
        for (String method : TAINTED_READERS) {
            try {
                verify(reporter, times(1)).doReportBug(
                        bugDefinition()
                                .bugType("SQL_INJECTION_HIBERNATE")
                                .inClass("StaticFieldOrder").inMethod(method)
                                .withPriority("High")
                                .build()
                );
            } catch (AssertionError e) {
                failures.add("missing High in " + method);
            }
        }
        for (String method : SAFE_READERS) {
            try {
                verify(reporter, never()).doReportBug(
                        bugDefinition()
                                .bugType("SQL_INJECTION_HIBERNATE")
                                .inClass("StaticFieldOrder").inMethod(method)
                                .build()
                );
            } catch (AssertionError e) {
                failures.add("unexpected report in " + method);
            }
        }
        assertTrue(failures.isEmpty(), failures.toString());
    }
}
