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

public class VariableIndexWriteBackTest extends BaseDetectorTest {

    @Test
    public void writeMutationBackToLoadedLocal() throws Exception {
        EasyBugReporter reporter = analyzeSample();

        for (String method : new String[] {"mutatedCopy", "mutatedLocal", "mutatedLocalThroughChain",
                "mutatedLocalThroughChainAfterUnknownValue"}) {
            verify(reporter).doReportBug(bugDefinition().bugType("XSS_SERVLET")
                    .inClass("VariableIndexWriteBack").inMethod(method).withPriority("High").build());
        }
    }

    /**
     * Known false negatives, the value of a method call does not refer to the receiver local
     */
    @Test
    public void doNotWriteCallResultMutationBackToReceiverLocal() throws Exception {
        EasyBugReporter reporter = analyzeSample();

        for (String method : new String[] {"mutatedMapEntry", "mutatedMapValue"}) {
            for (String priority : new String[] {"High", "Medium"}) {
                verify(reporter, never()).doReportBug(bugDefinition().bugType("XSS_SERVLET")
                        .inClass("VariableIndexWriteBack").inMethod(method).withPriority(priority).build());
            }
        }
    }

    @Test
    public void doNotWriteTransferResultMutationBackToArgumentLocal() throws Exception {
        EasyBugReporter reporter = analyzeSample();

        String[] methods = {
                "argumentOfTransferResultPassedToUnknownCode", "sourceOfMutatedCopy", "sourceOfStoredMutatedCopy"
        };

        for (String method : methods) {
            for (String priority : new String[] {"High", "Medium"}) {
                verify(reporter, never()).doReportBug(bugDefinition().bugType("XSS_SERVLET")
                        .inClass("VariableIndexWriteBack").inMethod(method).withPriority(priority).build());
            }
        }
    }

    private EasyBugReporter analyzeSample() throws Exception {
        String[] files = { getClassFilePath("testcode/taint/VariableIndexWriteBack") };

        EasyBugReporter reporter = spy(new SecurityReporter());
        analyze(files, reporter);

        return reporter;
    }
}
