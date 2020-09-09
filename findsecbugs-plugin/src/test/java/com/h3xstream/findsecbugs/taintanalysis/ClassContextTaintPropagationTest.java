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

import static org.mockito.Mockito.*;

public class ClassContextTaintPropagationTest extends BaseDetectorTest {

        @Test
        public void safe() throws Exception {
//                FindSecBugsGlobalConfig.getInstance().setDebugPrintInvocationVisited(true);
//                FindSecBugsGlobalConfig.getInstance().setDebugPrintInstructionVisited(true);
//                FindSecBugsGlobalConfig.getInstance().setDebugTaintState(true);

                //Locate test code
                String[] files = {
                        getClassFilePath("testcode/taint/ClassContextTaintPropagation"),
                        getClassFilePath("testcode/taint/ClassContextTaintPropagation$1"),
                        getClassFilePath("testcode/taint/ClassContextTaintPropagation$2"),
                        getClassFilePath("testcode/taint/ClassContextTaintPropagation$3"),
                        getClassFilePath("testcode/taint/ClassContextTaintPropagation$4"),
                        getClassFilePath("testcode/taint/ClassContextTaintPropagation$5"),
                        getClassFilePath("testcode/taint/ClassContextTaintPropagation$classA"),
                        getClassFilePath("testcode/taint/ClassContextTaintPropagation$classB")
                };

                //Run the analysis
                EasyBugReporter reporter = spy(new SecurityReporter());
                analyze(files, reporter);

                verify(reporter, never()).doReportBug(
                        bugDefinition().bugType("SQL_INJECTION_HIBERNATE")
                                .inClass("ClassContextTaintPropagation").inMethod("safeSetField")
                                .build());
                verify(reporter, never()).doReportBug(
                        bugDefinition().bugType("SQL_INJECTION_HIBERNATE")
                                .inClass("ClassContextTaintPropagation").inMethod("safeFieldSetter")
                                .build());
                verify(reporter, never()).doReportBug(
                        bugDefinition().bugType("SQL_INJECTION_HIBERNATE")
                                .inClass("ClassContextTaintPropagation").inMethod("safeConstructor")
                                .build());
                verify(reporter, never()).doReportBug(
                        bugDefinition().bugType("SQL_INJECTION_HIBERNATE")
                                .inClass("ClassContextTaintPropagation").inMethod("safeConcatField")
                                .build());
                verify(reporter, never()).doReportBug(
                        bugDefinition().bugType("SQL_INJECTION_HIBERNATE")
                                .inClass("ClassContextTaintPropagation").inMethod("safeNestedClasses")
                                .build());

                verify(reporter, times(1)).doReportBug(
                        bugDefinition().bugType("SQL_INJECTION_HIBERNATE")
                                .inClass("ClassContextTaintPropagation").inMethod("unknownUninitializedCrossContextField")
                                .withPriority("Medium") // Unknown taint for uninitialized field
                                .build());

                verify(reporter, never()).doReportBug(
                        bugDefinition().bugType("SQL_INJECTION_HIBERNATE")
                                .inClass("ClassContextTaintPropagation").inMethod("safeLocallyInitializedCrossContextField")
                                .build());
                verify(reporter, never()).doReportBug(
                        bugDefinition().bugType("SQL_INJECTION_HIBERNATE")
                                .inClass("ClassContextTaintPropagation").inMethod("safeLocallyInitializedCrossContextField2")
                                .build());


                verify(reporter, times(1)).doReportBug(
                        bugDefinition().bugType("SQL_INJECTION_HIBERNATE")
                                .inClass("ClassContextTaintPropagation").inMethod("unknownLocalVarWithSafeCallOnly")
                                .withPriority("Low") // Depends on static field but SAFE use only
                                .build());
                verify(reporter, times(1)).doReportBug(
                        bugDefinition().bugType("SQL_INJECTION_HIBERNATE")
                                .inClass("ClassContextTaintPropagation").inMethod("unknownLocalVarWithTaintedCall")
                                .withPriority("High") // Depends on static field and TAINTED use detected
                                .build());
                verify(reporter, times(1)).doReportBug(
                        bugDefinition().bugType("SQL_INJECTION_HIBERNATE")
                                .inClass("ClassContextTaintPropagation").inMethod("unknownLocalVarWithTaintedCall1")
                                .withPriority("High") // Depends on static field and TAINTED use detected
                                .build());
                verify(reporter, times(1)).doReportBug(
                        bugDefinition().bugType("SQL_INJECTION_HIBERNATE")
                                .inClass("ClassContextTaintPropagation").inMethod("unknownLocalVarWithTaintedCall2")
                                .withPriority("High") // Depends on static field and TAINTED use detected
                                .build());

                verify(reporter, never()).doReportBug(
                        bugDefinition().bugType("SQL_INJECTION_HIBERNATE")
                                .inClass("ClassContextTaintPropagation").inMethod("safeAnonymousClass")
                                .build());

                verify(reporter, times(1)).doReportBug(
                        bugDefinition().bugType("SQL_INJECTION_HIBERNATE")
                                .inClass("ClassContextTaintPropagation").inMethod("taintedAnonymousClass")
                                .withPriority("High")
                                .build());


                verify(reporter, times(1)).doReportBug(
                        bugDefinition().bugType("SQL_INJECTION_HIBERNATE")
                                .inClass("ClassContextTaintPropagation").inMethod("simplyUnknown")
                                .withPriority("Medium") // unknown
                                .build());
        }
}
