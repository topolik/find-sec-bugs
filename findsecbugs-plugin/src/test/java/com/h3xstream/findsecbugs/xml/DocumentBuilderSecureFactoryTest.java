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
package com.h3xstream.findsecbugs.xml;

import com.h3xstream.findbugs.test.BaseDetectorTest;
import com.h3xstream.findbugs.test.EasyBugReporter;
import org.testng.annotations.Test;

import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

public class DocumentBuilderSecureFactoryTest extends BaseDetectorTest {

    @Test
    public void avoidFalsePositiveOnSecureFactory() throws Exception {
        String[] files = {
                getClassFilePath("testcode/xxe/DocumentBuilderSecureFactory")
        };

        System.setProperty("findsecbugs.xxe.securefactories",
                "testcode/xxe/DocumentBuilderSecureFactory.newDocumentBuilderFactory");

        EasyBugReporter reporter = spy(new SecurityReporter());
        try {
            analyze(files, reporter);
        } finally {
            System.clearProperty("findsecbugs.xxe.securefactories");
        }

        verify(reporter, never()).doReportBug(
                bugDefinition()
                        .bugType("XXE_DOCUMENT")
                        .inClass("DocumentBuilderSecureFactory").inMethod("safeSecureFactory")
                        .build()
        );
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("XXE_DOCUMENT")
                        .inClass("DocumentBuilderSecureFactory").inMethod("unsafeDefaultFactory")
                        .build()
        );
    }
}
