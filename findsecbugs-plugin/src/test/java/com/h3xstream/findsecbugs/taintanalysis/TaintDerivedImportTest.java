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
import edu.umd.cs.findbugs.classfile.DescriptorFactory;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import static org.mockito.Mockito.*;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

public class TaintDerivedImportTest extends BaseDetectorTest {

    private static final String FILL = "testcode/taint/derivedimport/DerivedImportHelper.fill(Ljava/lang/StringBuilder;)V";
    private static final String GET = "testcode/taint/derivedimport/DerivedImportSource.get()Ljava/lang/String;";
    private static final String TOUCH = "testcode/taint/derivedimport/DerivedImportHelper.touch(Ljava/lang/String;)V";

    @Test
    public void derivedTaintRoundTrip() throws Exception {
        Taint taint = new Taint(Taint.State.UNKNOWN);
        taint.addParameter(0);
        taint.addParameter(2);
        taint.setNonParametricState(Taint.State.SAFE);
        taint.addTag(Taint.Tag.SQL_INJECTION_SAFE);
        taint.removeTag(Taint.Tag.URL_ENCODED);
        taint.setParameterTags(0, new HashSet<TaintTag>(Arrays.asList(Taint.Tag.SQL_INJECTION_SAFE, Taint.Tag.XSS_SAFE)));

        String formatted = TaintDataflowEngine.formatDerivedTaint(taint);
        assertEquals(formatted, "0[SQL_INJECTION_SAFE,XSS_SAFE],2,SAFE|+SQL_INJECTION_SAFE,-URL_ENCODED");

        TaintConfig taintConfig = new TaintConfig();
        taintConfig.loadDerived(new ByteArrayInputStream(("testcode/A.m(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;:"
                + formatted + "^1:" + formatted).getBytes(StandardCharsets.UTF_8)), className -> false);

        TaintMethodConfig config = taintConfig.get("testcode/A.m(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;");
        for (Taint loaded : Arrays.asList(config.getOutputTaint(), config.getParametersOutputTaints().get(1))) {
            assertEquals(loaded, taint);
            assertEquals(loaded.getTags(), taint.getTags());
            assertEquals(loaded.getTagsToRemove(), taint.getTagsToRemove());
            assertEquals(TaintDataflowEngine.formatDerivedTaint(loaded), formatted);
        }
        assertFalse(config.isConfigured());
        assertTrue(config.isParametersOutputTaintsProcessed());
    }

    @Test
    public void importFillsMissingSummariesOnly() throws Exception {
        String derived = "testcode/A.configured()Ljava/lang/String;:SAFE\n"
                + "testcode/A.excluded()Ljava/lang/String;:UNKNOWN\n"
                + "testcode/Own.analyzed()Ljava/lang/String;:SAFE\n"
                + "testcode/A.set(Ljava/lang/String;)V\n"
                + "testcode/A.fill(Ljava/lang/StringBuilder;)V^0:TAINTED\n"
                + "testcode/A.set(Ljava/lang/String;)V^0:TAINTED\n"
                + "testcode/A.bad()Ljava/lang/String;:NOT_A_STATE\n";

        TaintConfig taintConfig = new TaintConfig();
        taintConfig.setExcludedKeys(Collections.singleton("testcode/A.excluded()Ljava/lang/String;"));
        taintConfig.load(new ByteArrayInputStream(("testcode/A.configured()Ljava/lang/String;:TAINTED\n"
                + "testcode/A.excluded()Ljava/lang/String;:SAFE\n").getBytes(StandardCharsets.UTF_8)), false, "custom", true);
        taintConfig.loadDerived(new ByteArrayInputStream(derived.getBytes(StandardCharsets.UTF_8)),
                className -> className.equals("testcode/Own"));

        assertEquals(taintConfig.getImportedEntries(), 3);
        assertEquals(taintConfig.getImportSkippedEntries(), 1);
        assertEquals(taintConfig.getImportPresentEntries(), 2);
        assertEquals(taintConfig.getImportBadEntries(), 1);

        TaintMethodConfig configured = taintConfig.get("testcode/A.configured()Ljava/lang/String;");
        assertTrue(configured.isConfigured());
        assertTrue(configured.getOutputTaint().isTainted());

        TaintMethodConfig excluded = taintConfig.get("testcode/A.excluded()Ljava/lang/String;");
        assertFalse(excluded.isConfigured());
        assertTrue(excluded.getOutputTaint().isUnknown());

        assertFalse(taintConfig.containsKey("testcode/Own.analyzed()Ljava/lang/String;"));
        assertFalse(taintConfig.containsKey("testcode/A.bad()Ljava/lang/String;"));

        TaintMethodConfig set = taintConfig.get("testcode/A.set(Ljava/lang/String;)V");
        assertNull(set.getOutputTaint());
        assertTrue(set.getParametersOutputTaints().isEmpty());
        assertTrue(set.isParametersOutputTaintsProcessed());
        assertTrue(set.isInformative());

        TaintMethodConfig fill = taintConfig.get("testcode/A.fill(Ljava/lang/StringBuilder;)V");
        assertTrue(fill.getParametersOutputTaints().get(0).isTainted());
    }

    @Test
    public void importedVoidSummaryKeepsArgumentSafe() throws Exception {
        String[] files = {
                getClassFilePath("testcode/taint/derivedimport/DerivedImportSamples")
        };

        EasyBugReporter reporter = spy(new SecurityReporter());
        analyze(files, reporter);

        //Unknown method, its arguments may be mutated
        verify(reporter, atLeastOnce()).doReportBug(bugDefinition().bugType("COMMAND_INJECTION")
                .inClass("DerivedImportSamples").inMethod("fillCommand").build());

        reporter = spy(new SecurityReporter());
        analyzeWithImport(files, reporter, FILL);

        verify(reporter, never()).doReportBug(bugDefinition().bugType("COMMAND_INJECTION")
                .inClass("DerivedImportSamples").inMethod("fillCommand").build());
    }

    @Test
    public void importedSummaryChangesFinding() throws Exception {
        String[] files = {
                getClassFilePath("testcode/taint/derivedimport/DerivedImportSamples")
        };

        EasyBugReporter reporter = spy(new SecurityReporter());
        analyzeWithImport(files, reporter, GET + ":SAFE");

        verify(reporter, never()).doReportBug(bugDefinition().bugType("COMMAND_INJECTION")
                .inClass("DerivedImportSamples").inMethod("sourceCommand").build());
    }

    @Test
    public void importedArgumentSummaryMergesAtJoin() throws Exception {
        String[] files = {
                getClassFilePath("testcode/taint/derivedimport/DerivedImportSamples")
        };

        EasyBugReporter reporter = spy(new SecurityReporter());
        analyzeWithImport(files, reporter, TOUCH + "^0:0");

        //The argument rewritten by the imported summary joins the untouched one before the sink
        verify(reporter, atLeastOnce()).doReportBug(bugDefinition().bugType("COMMAND_INJECTION")
                .inClass("DerivedImportSamples").inMethod("touchCommand").build());
    }

    @Test
    public void importSkipsAnalyzedClasses() throws Exception {
        String[] files = {
                getClassFilePath("testcode/taint/derivedimport/DerivedImportSamples"),
                getClassFilePath("testcode/taint/derivedimport/DerivedImportSource")
        };

        EasyBugReporter reporter = spy(new SecurityReporter());
        analyzeWithImport(files, reporter, GET + ":SAFE");

        //The analyzed interface has no derived summary, the imported one is stale
        verify(reporter, atLeastOnce()).doReportBug(bugDefinition().bugType("COMMAND_INJECTION")
                .inClass("DerivedImportSamples").inMethod("sourceCommand").build());
    }

    @Test
    public void importDoesNotReportMissingClasses() throws Exception {
        String[] files = {
                getClassFilePath("testcode/taint/derivedimport/DerivedImportSamples")
        };

        EasyBugReporter reporter = spy(new SecurityReporter());
        analyzeWithImport(files, reporter, "testcode/taint/derivedimport/DerivedImportMissing.get()Ljava/lang/String;:SAFE");

        //Summaries of the classes outside the classpath are common in a shared feed
        verify(reporter, never()).reportMissingClass(
                DescriptorFactory.createClassDescriptor("testcode/taint/derivedimport/DerivedImportMissing"));
    }

    @Test
    public void importFillsExcludedCustomKey() throws Exception {
        URL configUrl = this.getClass().getResource("/com/h3xstream/findsecbugs/taintanalysis/CustomConfig.txt");
        File configFile = new File(configUrl.toURI());
        File excludeFile = File.createTempFile("exclude-config-keys", ".txt");
        Files.write(excludeFile.toPath(), Collections.singletonList(
                "testcode/xpath/XPathSuperSecureUtil.encodeForXPath(Ljava/lang/String;)Ljava/lang/String;"),
                StandardCharsets.UTF_8);

        FindSecBugsGlobalConfig.getInstance().setCustomConfigFile(configFile.getCanonicalPath());
        FindSecBugsGlobalConfig.getInstance().setTaintExcludeConfigKeys(excludeFile.getAbsolutePath());
        try {
            String[] files = {
                    getClassFilePath("testcode/xpath/XPathJavaxCustomSafe")
            };

            EasyBugReporter reporter = spy(new SecurityReporter());
            analyzeWithImport(files, reporter,
                    "testcode/xpath/XPathSuperSecureUtil.encodeForXPath(Ljava/lang/String;)Ljava/lang/String;:0|+XPATH_INJECTION_SAFE");

            verify(reporter, never()).doReportBug(bugDefinition().bugType("XPATH_INJECTION")
                    .inClass("XPathJavaxCustomSafe").inMethod("main").build());
        } finally {
            FindSecBugsGlobalConfig.getInstance().setCustomConfigFile("");
            FindSecBugsGlobalConfig.getInstance().setTaintExcludeConfigKeys(null);
            excludeFile.delete();
        }
    }

    private void analyzeWithImport(String[] files, EasyBugReporter reporter, String... lines) throws Exception {
        File importFile = File.createTempFile("derived-config", ".txt");
        Files.write(importFile.toPath(), Arrays.asList(lines), StandardCharsets.UTF_8);
        FindSecBugsGlobalConfig.getInstance().setTaintImportConfigFile(importFile.getAbsolutePath());
        try {
            analyze(files, reporter);
        } finally {
            FindSecBugsGlobalConfig.getInstance().setTaintImportConfigFile(null);
            importFile.delete();
        }
    }
}
