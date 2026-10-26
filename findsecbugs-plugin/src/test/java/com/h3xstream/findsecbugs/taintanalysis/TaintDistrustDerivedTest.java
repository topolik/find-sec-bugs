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
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.GZIPOutputStream;

import static org.mockito.Mockito.*;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
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
                getClassFilePath(PACKAGE + "DistrustHolder"),
                getClassFilePath(PACKAGE + "DistrustMergeSamples"),
                getClassFilePath(PACKAGE + "DistrustSafeBase"),
                getClassFilePath(PACKAGE + "DistrustSafeOverrider"),
                getClassFilePath(PACKAGE + "DistrustPendingBase"),
                getClassFilePath(PACKAGE + "DistrustPendingOverrider"),
                getClassFilePath(PACKAGE + "DistrustImplementorsSamples"),
                getClassFilePath(PACKAGE + "DistrustSource"),
                getClassFilePath(PACKAGE + "DistrustSourceImpl"),
                getClassFilePath(PACKAGE + "DistrustCommand"),
                getClassFilePath(PACKAGE + "DistrustCommandSource"),
                getClassFilePath(PACKAGE + "DistrustFunctionalSource"),
                getClassFilePath(PACKAGE + "DistrustEqualsSource"),
                getClassFilePath(PACKAGE + "DistrustFunctionalSourceImpl"),
                getClassFilePath(PACKAGE + "DistrustAbstractSource"),
                getClassFilePath(PACKAGE + "DistrustDefaultSource"),
                getClassFilePath(PACKAGE + "DistrustDefaultSourceImpl")
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
    public void mergedOverridersSummaryIsApplied() throws Exception {
        EasyBugReporter reporter = spy(new SecurityReporter());
        analyzeDistrusting("override", getFiles(), reporter);

        for (String method : new String[] {"mergedCommand", "mergedAppendCommand"}) {
            verify(reporter, atLeastOnce()).doReportBug(bugDefinition().bugType("COMMAND_INJECTION")
                    .inClass("DistrustMergeSamples").inMethod(method).build());
        }

        reporter = spy(new SecurityReporter());
        analyzeDistrusting("merge", getFiles(), reporter);

        //Every implementation in the analyzed code is safe
        for (String method : new String[] {"mergedCommand", "mergedAppendCommand"}) {
            verify(reporter, never()).doReportBug(bugDefinition().bugType("COMMAND_INJECTION")
                    .inClass("DistrustMergeSamples").inMethod(method).build());
        }
        //An implementation is unknown or not analyzed yet
        for (String method : new String[] {"mergedUnknownCommand", "pendingCommand"}) {
            verify(reporter, atLeastOnce()).doReportBug(bugDefinition().bugType("COMMAND_INJECTION")
                    .inClass("DistrustMergeSamples").inMethod(method).build());
        }
    }

    @Test
    public void cappedOverridersSummaryIsDistrusted() throws Exception {
        FindSecBugsGlobalConfig.getInstance().setTaintDistrustDerivedMaxMerged(0);
        try {
            EasyBugReporter reporter = spy(new SecurityReporter());
            analyzeDistrusting("merge", getFiles(), reporter);

            verify(reporter, atLeastOnce()).doReportBug(bugDefinition().bugType("COMMAND_INJECTION")
                    .inClass("DistrustMergeSamples").inMethod("mergedCommand").build());
        } finally {
            FindSecBugsGlobalConfig.getInstance().setTaintDistrustDerivedMaxMerged(16);
        }
    }

    @Test
    public void mergedSummariesAreWritten() throws Exception {
        File distrustFile = File.createTempFile("distrusted-derived", ".txt");
        FindSecBugsGlobalConfig.getInstance().setTaintDistrustDerivedFile(distrustFile.getAbsolutePath());
        try {
            EasyBugReporter reporter = spy(new SecurityReporter());
            analyzeDistrusting("merge", getFiles(), reporter);

            List<String> lines = Files.readAllLines(distrustFile.toPath(), StandardCharsets.UTF_8);
            assertTrue(lines.contains("merge\t" + PACKAGE + "DistrustSafeBase.command()Ljava/lang/String;\tmerged"),
                    lines.toString());
            assertTrue(lines.contains("merge\t" + PACKAGE + "DistrustSafeBase.append(Ljava/lang/StringBuilder;)V"
                    + "\tmerged"), lines.toString());
            assertTrue(lines.contains("merge\t" + PACKAGE + "DistrustPendingBase.command()Ljava/lang/String;"
                    + "\tpending"), lines.toString());
        } finally {
            FindSecBugsGlobalConfig.getInstance().setTaintDistrustDerivedFile(null);
            distrustFile.delete();
        }
    }

    @Test
    public void prepassResolvesPendingOverriders() throws Exception {
        File distrustFile = File.createTempFile("distrusted-derived", ".txt");
        FindSecBugsGlobalConfig.getInstance().setTaintDistrustDerivedFile(distrustFile.getAbsolutePath());
        FindSecBugsGlobalConfig.getInstance().setTaintPrepass(true);
        try {
            EasyBugReporter reporter = spy(new SecurityReporter());
            analyzeDistrusting("merge", getFiles(), reporter);

            //The overrider analyzed after the call site is merged, the prepass writes no outcome
            verify(reporter, never()).doReportBug(bugDefinition().bugType("COMMAND_INJECTION")
                    .inClass("DistrustMergeSamples").inMethod("pendingCommand").build());
            List<String> lines = Files.readAllLines(distrustFile.toPath(), StandardCharsets.UTF_8);
            assertTrue(lines.contains("merge\t" + PACKAGE + "DistrustPendingBase.command()Ljava/lang/String;"
                    + "\tmerged"), lines.toString());
            assertFalse(lines.contains("merge\t" + PACKAGE + "DistrustPendingBase.command()Ljava/lang/String;"
                    + "\tpending"), lines.toString());
        } finally {
            FindSecBugsGlobalConfig.getInstance().setTaintPrepass(false);
            FindSecBugsGlobalConfig.getInstance().setTaintDistrustDerivedFile(null);
            distrustFile.delete();
        }
    }

    @Test
    public void mergedImplementorsSummaryIsApplied() throws Exception {
        EasyBugReporter reporter = spy(new SecurityReporter());
        analyze(getFiles(), reporter);

        for (String method : new String[] {"implementorsCommand", "abstractCommand"}) {
            verify(reporter, atLeastOnce()).doReportBug(bugDefinition().bugType("COMMAND_INJECTION")
                    .inClass("DistrustImplementorsSamples").inMethod(method).build());
        }

        reporter = spy(new SecurityReporter());
        analyzeDistrusting("implementors", getFiles(), reporter);

        //Every implementation in the analyzed code is safe
        for (String method : new String[] {"implementorsCommand", "abstractCommand"}) {
            verify(reporter, never()).doReportBug(bugDefinition().bugType("COMMAND_INJECTION")
                    .inClass("DistrustImplementorsSamples").inMethod(method).build());
        }
        //An inherited implementation is unknown or a lambda expression may implement the method
        for (String method : new String[] {"implementorsAppendCommand", "functionalCommand", "equalsCommand"}) {
            verify(reporter, atLeastOnce()).doReportBug(bugDefinition().bugType("COMMAND_INJECTION")
                    .inClass("DistrustImplementorsSamples").inMethod(method).build());
        }
    }

    @Test
    public void mergedImplementorsSummariesAreWritten() throws Exception {
        File distrustFile = File.createTempFile("distrusted-derived", ".txt");
        FindSecBugsGlobalConfig.getInstance().setTaintDistrustDerivedFile(distrustFile.getAbsolutePath());
        try {
            EasyBugReporter reporter = spy(new SecurityReporter());
            analyzeDistrusting("implementors", getFiles(), reporter);

            List<String> lines = Files.readAllLines(distrustFile.toPath(), StandardCharsets.UTF_8);
            for (String line : new String[] {
                    "DistrustSource.command()Ljava/lang/String;\tmerged",
                    "DistrustSource.append(Ljava/lang/StringBuilder;)V\tmerged",
                    "DistrustAbstractSource.command()Ljava/lang/String;\tmerged",
                    "DistrustFunctionalSource.command()Ljava/lang/String;\tfunctional",
                    "DistrustEqualsSource.command()Ljava/lang/String;\tfunctional"}) {
                assertTrue(lines.contains("implementors\t" + PACKAGE + line), lines.toString());
            }
            assertEquals(lines.size(), new HashSet<String>(lines).size());
        } finally {
            FindSecBugsGlobalConfig.getInstance().setTaintDistrustDerivedFile(null);
            distrustFile.delete();
        }
    }

    @Test
    public void externalOverridersAreMerged() throws Exception {
        File distrustFile = File.createTempFile("distrusted-derived", ".txt");
        File overridersFile = createOverridersFile(
                PACKAGE + "DistrustSource.command()Ljava/lang/String;\t" + PACKAGE + "DistrustMissing",
                PACKAGE + "DistrustAbstractSource.command()Ljava/lang/String;\t?",
                PACKAGE + "DistrustBase.finalCommand()Ljava/lang/String;\t?");
        FindSecBugsGlobalConfig.getInstance().setTaintDistrustDerivedFile(distrustFile.getAbsolutePath());
        FindSecBugsGlobalConfig.getInstance().setTaintOverridersFile(overridersFile.getAbsolutePath());
        try {
            EasyBugReporter reporter = spy(new SecurityReporter());
            analyzeDistrusting("override,implementors", getFiles(), reporter);

            //The implementation outside the analyzed code is not known
            for (String method : new String[] {"implementorsCommand", "abstractCommand"}) {
                verify(reporter, atLeastOnce()).doReportBug(bugDefinition().bugType("COMMAND_INJECTION")
                        .inClass("DistrustImplementorsSamples").inMethod(method).build());
            }
            //The final method is not overridden
            verify(reporter, never()).doReportBug(bugDefinition().bugType("COMMAND_INJECTION")
                    .inClass("DistrustSamples").inMethod("finalCommand").build());

            List<String> lines = Files.readAllLines(distrustFile.toPath(), StandardCharsets.UTF_8);
            assertTrue(lines.contains("implementors\t" + PACKAGE + "DistrustSource.command()Ljava/lang/String;"
                    + "\tabsent"), lines.toString());
            assertTrue(lines.contains("implementors\t" + PACKAGE + "DistrustAbstractSource.command()Ljava/lang/String;"
                    + "\tunresolved"), lines.toString());
        } finally {
            FindSecBugsGlobalConfig.getInstance().setTaintDistrustDerivedFile(null);
            FindSecBugsGlobalConfig.getInstance().setTaintOverridersFile(null);
            distrustFile.delete();
            overridersFile.delete();
        }
    }

    @Test
    public void importedOverriderSummaryIsMerged() throws Exception {
        File distrustFile = File.createTempFile("distrusted-derived", ".txt");
        File importFile = File.createTempFile("derived-config", ".txt");
        Files.write(importFile.toPath(), Collections.singletonList(
                PACKAGE + "DistrustMissing.command()Ljava/lang/String;:SAFE"), StandardCharsets.UTF_8);
        File overridersFile = createOverridersFile(
                PACKAGE + "DistrustSource.command()Ljava/lang/String;\t" + PACKAGE + "DistrustMissing");
        FindSecBugsGlobalConfig.getInstance().setTaintDistrustDerivedFile(distrustFile.getAbsolutePath());
        FindSecBugsGlobalConfig.getInstance().setTaintImportConfigFile(importFile.getAbsolutePath());
        FindSecBugsGlobalConfig.getInstance().setTaintOverridersFile(overridersFile.getAbsolutePath());
        try {
            EasyBugReporter reporter = spy(new SecurityReporter());
            analyzeDistrusting("implementors", getFiles(), reporter);

            //The imported summary of the implementation outside the analyzed code is merged
            verify(reporter, never()).doReportBug(bugDefinition().bugType("COMMAND_INJECTION")
                    .inClass("DistrustImplementorsSamples").inMethod("implementorsCommand").build());

            List<String> lines = Files.readAllLines(distrustFile.toPath(), StandardCharsets.UTF_8);
            assertTrue(lines.contains("implementors\t" + PACKAGE + "DistrustSource.command()Ljava/lang/String;"
                    + "\tmerged"), lines.toString());
        } finally {
            FindSecBugsGlobalConfig.getInstance().setTaintDistrustDerivedFile(null);
            FindSecBugsGlobalConfig.getInstance().setTaintImportConfigFile(null);
            FindSecBugsGlobalConfig.getInstance().setTaintOverridersFile(null);
            distrustFile.delete();
            importFile.delete();
            overridersFile.delete();
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

    private File createOverridersFile(String... lines) throws Exception {
        File overridersFile = File.createTempFile("overriders", ".txt.gz");
        OutputStream output = new GZIPOutputStream(Files.newOutputStream(overridersFile.toPath()));
        try {
            output.write(String.join("\n", lines).getBytes(StandardCharsets.UTF_8));
        } finally {
            output.close();
        }
        return overridersFile;
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
