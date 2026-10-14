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
import org.testng.annotations.Test;

import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

public class StaticCallLookupTest extends BaseDetectorTest {

    @Test
    public void lookUpStaticCallsByDeclaringClass() throws Exception {
        String[] files = {
                getClassFilePath("testcode/taint/StaticCallLookup")
        };

        EasyBugReporter reporter = spy(new SecurityReporter());
        analyze(files, reporter);

        verify(reporter, never()).doReportBug(
                bugDefinition()
                        .bugType("XSS_SERVLET")
                        .inClass("StaticCallLookup").inMethod("sanitized")
                        .build()
        );
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("XSS_SERVLET")
                        .inClass("StaticCallLookup").inMethod("transferred")
                        .withPriority("High")
                        .build()
        );
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("PATH_TRAVERSAL_IN")
                        .inClass("StaticCallLookup").inMethod("resolve")
                        .withPriority("High")
                        .build()
        );
    }
}
