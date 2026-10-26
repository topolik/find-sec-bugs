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
import edu.umd.cs.findbugs.classfile.ClassDescriptor;
import org.mockito.ArgumentCaptor;
import org.testng.annotations.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.mockito.Mockito.*;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

public class TaintDistrustDerivedTest extends BaseDetectorTest {

    private static final String PACKAGE = "testcode/taint/distrustderived/";

    private String[] getFiles() {
        return new String[] {
                getClassFilePath(PACKAGE + "DistrustSamples"),
                getClassFilePath(PACKAGE + "DistrustBase"),
                getClassFilePath(PACKAGE + "DistrustOverrider"),
                getClassFilePath(PACKAGE + "DistrustLeaf"),
                getClassFilePath(PACKAGE + "DistrustDefault"),
                getClassFilePath(PACKAGE + "DistrustDefaultImpl"),
                getClassFilePath(PACKAGE + "DistrustHolder")
        };
    }

    @Test
    public void overriddenMethodSummaryIsDistrusted() throws Exception {
        EasyBugReporter reporter = spy(new SecurityReporter());
        analyze(getFiles(), reporter);

        for (String method : new String[] {"overriddenCommand", "defaultCommand"}) {
            verify(reporter, never()).doReportBug(bugDefinition().bugType("COMMAND_INJECTION")
                    .inClass("DistrustSamples").inMethod(method).build());
        }

        reporter = spy(new SecurityReporter());
        analyzeDistrusting("override", getFiles(), reporter);

        //The subtype in the analyzed code may be the runtime receiver
        for (String method : new String[] {"overriddenCommand", "defaultCommand"}) {
            verify(reporter, atLeastOnce()).doReportBug(bugDefinition().bugType("COMMAND_INJECTION")
                    .inClass("DistrustSamples").inMethod(method).build());
        }
    }

    @Test
    public void notOverriddenMethodSummaryIsKept() throws Exception {
        EasyBugReporter reporter = spy(new SecurityReporter());
        analyzeDistrusting("override,constructor", getFiles(), reporter);

        for (String method : new String[] {"finalCommand", "leafCommand"}) {
            verify(reporter, never()).doReportBug(bugDefinition().bugType("COMMAND_INJECTION")
                    .inClass("DistrustSamples").inMethod(method).build());
        }
    }

    @Test
    public void constructorSummaryIsDistrusted() throws Exception {
        EasyBugReporter reporter = spy(new SecurityReporter());
        analyzeDistrusting("override", getFiles(), reporter);

        //The derived summary does not describe the constructed object
        verify(reporter, never()).doReportBug(bugDefinition().bugType("COMMAND_INJECTION")
                .inClass("DistrustSamples").inMethod("constructedCommand").build());

        reporter = spy(new SecurityReporter());
        analyzeDistrusting("constructor", getFiles(), reporter);

        verify(reporter, atLeastOnce()).doReportBug(bugDefinition().bugType("COMMAND_INJECTION")
                .inClass("DistrustSamples").inMethod("constructedCommand").build());
    }

    @Test
    public void distrustedSummariesAreWritten() throws Exception {
        File distrustFile = File.createTempFile("distrusted-derived", ".txt");
        FindSecBugsGlobalConfig.getInstance().setTaintDistrustDerivedFile(distrustFile.getAbsolutePath());
        try {
            EasyBugReporter reporter = spy(new SecurityReporter());
            analyzeDistrusting("override,constructor", getFiles(), reporter);

            List<String> lines = Files.readAllLines(distrustFile.toPath(), StandardCharsets.UTF_8);
            assertTrue(lines.contains("override\t" + PACKAGE + "DistrustBase.command()Ljava/lang/String;\t1\t"
                    + PACKAGE + "DistrustOverrider"), lines.toString());
            assertTrue(lines.contains("override\t" + PACKAGE + "DistrustDefault.command()Ljava/lang/String;\t1\t"
                    + PACKAGE + "DistrustDefaultImpl"), lines.toString());
            assertTrue(lines.contains("constructor\t" + PACKAGE + "DistrustHolder.<init>(Ljava/lang/String;)V"),
                    lines.toString());
            assertEquals(lines.size(), new HashSet<String>(lines).size());
        } finally {
            FindSecBugsGlobalConfig.getInstance().setTaintDistrustDerivedFile(null);
            distrustFile.delete();
        }
    }

    @Test
    public void missingReceiverClassIsNotReported() throws Exception {
        String[] files = {
                getClassFilePath("testcode/taint/derivedimport/DerivedImportSamples")
        };
        File importFile = File.createTempFile("derived-config", ".txt");
        Files.write(importFile.toPath(), Collections.singletonList(
                "testcode/taint/derivedimport/DerivedImportSource.get()Ljava/lang/String;:SAFE"),
                StandardCharsets.UTF_8);
        FindSecBugsGlobalConfig.getInstance().setTaintImportConfigFile(importFile.getAbsolutePath());
        try {
            EasyBugReporter reporter = spy(new SecurityReporter());
            analyze(files, reporter);
            Set<ClassDescriptor> missingClasses = getMissingClasses(reporter);

            reporter = spy(new SecurityReporter());
            analyzeDistrusting("override", files, reporter);

            //The subtypes of a class outside the classpath are not known
            verify(reporter, atLeastOnce()).doReportBug(bugDefinition().bugType("COMMAND_INJECTION")
                    .inClass("DerivedImportSamples").inMethod("sourceCommand").build());
            assertEquals(getMissingClasses(reporter), missingClasses);
        } finally {
            FindSecBugsGlobalConfig.getInstance().setTaintImportConfigFile(null);
            importFile.delete();
        }
    }

    private Set<ClassDescriptor> getMissingClasses(EasyBugReporter reporter) {
        ArgumentCaptor<ClassDescriptor> captor = ArgumentCaptor.forClass(ClassDescriptor.class);
        verify(reporter, atLeast(0)).reportMissingClass(captor.capture());
        return new HashSet<ClassDescriptor>(captor.getAllValues());
    }

    private void analyzeDistrusting(String kinds, String[] files, EasyBugReporter reporter) throws Exception {
        FindSecBugsGlobalConfig.getInstance().setTaintDistrustDerived(kinds);
        try {
            analyze(files, reporter);
        } finally {
            FindSecBugsGlobalConfig.getInstance().setTaintDistrustDerived(null);
        }
    }
}
