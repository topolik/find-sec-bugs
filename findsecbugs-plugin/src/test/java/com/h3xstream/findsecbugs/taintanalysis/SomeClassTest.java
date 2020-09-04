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

public class SomeClassTest extends BaseDetectorTest {

        @Test
        public void safe() throws Exception {
//                FindSecBugsGlobalConfig.getInstance().setDebugPrintInvocationVisited(true);
//                FindSecBugsGlobalConfig.getInstance().setDebugPrintInstructionVisited(true);
//                FindSecBugsGlobalConfig.getInstance().setDebugTaintState(true);

                //Locate test code
                String[] files = {
                        getClassFilePath("testcode/taint/SomeClass"),
                        getClassFilePath("testcode/taint/SomeClass$classA"),
                        getClassFilePath("testcode/taint/SomeClass$classB")
                };

                //Run the analysis
                EasyBugReporter reporter = spy(new SecurityReporter());
                analyze(files, reporter);

//
//                verify(reporter, never()).doReportBug(
//                        bugDefinition()
//                                .inClass("SomeClass").inMethod("safe")
//                                .build());

//                verify(reporter, times(1)).doReportBug(
//                        bugDefinition().bugType("SQL_INJECTION_HIBERNATE")
//                                .inClass("SomeClass").inMethod("tainted2")
//                                .withPriority("High")
//                                .build());
        }
}
