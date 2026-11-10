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
import org.testng.annotations.Test;

import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

public class MustAliasTest extends BaseDetectorTest {

    private static final String[] MUST_ALIAS_METHODS = {
            "aliasPassedToMutatingCallee", "mutatedAliasInLoop", "mutatedAliasOfAlias", "mutatedArrayAlias",
            "mutatedBuilderAlias", "mutatedBuilderAliasThroughChain", "mutatedCastAlias", "mutatedFieldLoadedTwice",
            "mutatedListAlias", "mutatedOriginalReadThroughAlias", "mutatedParameterAlias", "mutatedStackAlias"
    };

    @Test
    public void writeMutationToMustAliases() throws Exception {
        EasyBugReporter reporter = analyzeSample(true);

        for (String method : MUST_ALIAS_METHODS) {
            verify(reporter).doReportBug(bugDefinition().bugType("XSS_SERVLET")
                    .inClass("MustAlias").inMethod(method).withPriority("High").build());
        }

        verify(reporter).doReportBug(bugDefinition().bugType("XSS_SERVLET")
                .inClass("MustAlias").inMethod("aliasPassedToUnknownCode").withPriority("Medium").build());
    }

    @Test
    public void doNotWriteMutationToMayAliases() throws Exception {
        EasyBugReporter reporter = analyzeSample(true);

        verifyNotReported(reporter, "mutatedAliasOnOnePath", "mutatedReassignedAlias", "mutatedReassignedParameter");
    }

    @Test
    public void doNotLowerTaintOfMustAliases() throws Exception {

        // a mutation replacing the taint of one alias, like clear, keeps the taint of the others as when disabled

        for (boolean mustAlias : new boolean[] {true, false}) {
            EasyBugReporter reporter = analyzeSample(mustAlias);

            for (String method : new String[] {"clearedAlias", "filledAlias"}) {
                verify(reporter).doReportBug(bugDefinition().bugType("XSS_SERVLET")
                        .inClass("MustAlias").inMethod(method).withPriority("High").build());
            }
        }
    }

    @Test
    public void doNotWriteMutationToMustAliasesWhenDisabled() throws Exception {
        EasyBugReporter reporter = analyzeSample(false);

        for (String method : MUST_ALIAS_METHODS) {
            if (!method.equals("mutatedFieldLoadedTwice")) {
                verifyNotReported(reporter, method);
            }
        }

        verifyNotReported(reporter, "aliasPassedToUnknownCode");

        // the field is unknown, so the local read from it stays unknown without the write

        verify(reporter).doReportBug(bugDefinition().bugType("XSS_SERVLET")
                .inClass("MustAlias").inMethod("mutatedFieldLoadedTwice").withPriority("Medium").build());
        verify(reporter, never()).doReportBug(bugDefinition().bugType("XSS_SERVLET")
                .inClass("MustAlias").inMethod("mutatedFieldLoadedTwice").withPriority("High").build());
    }

    private EasyBugReporter analyzeSample(boolean mustAlias) throws Exception {
        String[] files = { getClassFilePath("testcode/taint/MustAlias") };

        EasyBugReporter reporter = spy(new SecurityReporter());

        boolean defaultMustAlias = FindSecBugsGlobalConfig.getInstance().isTaintMustAlias();
        FindSecBugsGlobalConfig.getInstance().setTaintMustAlias(mustAlias);

        try {
            analyze(files, reporter);
        } finally {
            FindSecBugsGlobalConfig.getInstance().setTaintMustAlias(defaultMustAlias);
        }

        return reporter;
    }

    private void verifyNotReported(EasyBugReporter reporter, String... methods) {
        for (String method : methods) {
            for (String priority : new String[] {"High", "Medium"}) {
                verify(reporter, never()).doReportBug(bugDefinition().bugType("XSS_SERVLET")
                        .inClass("MustAlias").inMethod(method).withPriority(priority).build());
            }
        }
    }
}
