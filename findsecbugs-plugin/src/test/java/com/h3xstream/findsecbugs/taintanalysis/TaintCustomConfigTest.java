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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.StringWriter;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.HashSet;

import static org.mockito.Mockito.*;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class TaintCustomConfigTest extends BaseDetectorTest {

    @Test
    public void withCustomConfigEnable() throws Exception {
        URL configUrl = this.getClass().getResource("/com/h3xstream/findsecbugs/taintanalysis/CustomConfig.txt");
        File configFile = new File(configUrl.toURI());

        FindSecBugsGlobalConfig.getInstance().setCustomConfigFile(configFile.getCanonicalPath());

        //Locate test code
        String[] files = {
                getClassFilePath("testcode/xpath/XPathJavaxCustomSafe")
        };

        //Run the analysis
        EasyBugReporter reporter = spy(new SecurityReporter());
        analyze(files, reporter);

        //Assertions
        verify(reporter,never()).doReportBug(
                bugDefinition().bugType("XPATH_INJECTION")
                        .inClass("XPathJavaxCustomSafe").inMethod("main")
                        .build()
        );

        FindSecBugsGlobalConfig.getInstance().setCustomConfigFile(""); //Avoid potential conflicts with other tests.
    }

    @Test
    public void withCustomConfigDisable() throws Exception {
//        URL configUrl = this.getClass().getResource("/com/h3xstream/findsecbugs/taintanalysis/CustomConfig.txt");
//        File configFile = new File(configUrl.toURI());
//
//        FindSecBugsGlobalConfig.getInstance().setCustomConfigFile(configFile.getCanonicalPath());

        //Locate test code
        String[] files = {
                getClassFilePath("testcode/xpath/XPathJavaxCustomSafe")
        };

        //Run the analysis
        EasyBugReporter reporter = spy(new SecurityReporter());
        analyze(files, reporter);

        //Assertions
        verify(reporter,times(2)).doReportBug(
                bugDefinition().bugType("XPATH_INJECTION")
                        .inClass("XPathJavaxCustomSafe").inMethod("main")
                        .build()
        );
    }

    @Test
    public void withExcludedConfigKeys() throws Exception {
        URL configUrl = this.getClass().getResource("/com/h3xstream/findsecbugs/taintanalysis/CustomConfig.txt");
        File configFile = new File(configUrl.toURI());
        File excludeFile = File.createTempFile("exclude-config-keys", ".txt");
        Files.write(excludeFile.toPath(), Arrays.asList(
                "# prune candidates",
                "",
                "testcode/xpath/XPathSuperSecureUtil.encodeForXPath(Ljava/lang/String;)Ljava/lang/String;"),
                StandardCharsets.UTF_8);

        FindSecBugsGlobalConfig.getInstance().setCustomConfigFile(configFile.getCanonicalPath());
        FindSecBugsGlobalConfig.getInstance().setTaintExcludeConfigKeys(excludeFile.getAbsolutePath());
        try {
            String[] files = {
                    getClassFilePath("testcode/xpath/XPathJavaxCustomSafe")
            };

            EasyBugReporter reporter = spy(new SecurityReporter());
            analyze(files, reporter);

            //The excluded sanitizer no longer hides the injections
            verify(reporter,times(2)).doReportBug(
                    bugDefinition().bugType("XPATH_INJECTION")
                            .inClass("XPathJavaxCustomSafe").inMethod("main")
                            .build()
            );
        } finally {
            FindSecBugsGlobalConfig.getInstance().setCustomConfigFile("");
            FindSecBugsGlobalConfig.getInstance().setTaintExcludeConfigKeys(null);
            excludeFile.delete();
        }
    }

    @Test
    public void excludedKeysDropCustomEntriesOnly() throws Exception {
        String config = "testcode/A.excluded()Ljava/lang/String;:SAFE\n"
                + "testcode/A.kept()Ljava/lang/String;:SAFE\n"
                + "testcode/A.lookup(\"x\"):SAFE@testcode/B\n"
                + "testcode/A.lookup(\"y\"):SAFE@testcode/B\n";

        TaintConfig taintConfig = new TaintConfig();
        TaintConfigUsage usage = new TaintConfigUsage(true);
        taintConfig.setUsage(usage);
        taintConfig.setExcludedKeys(new HashSet<String>(Arrays.asList(
                "testcode/A.excluded()Ljava/lang/String;",
                "testcode/A.lookup(\"x\")@testcode/B",
                "testcode/A.missing()Ljava/lang/String;")));
        taintConfig.load(new ByteArrayInputStream("testcode/A.excluded()Ljava/lang/String;:TAINTED\n"
                .getBytes(StandardCharsets.UTF_8)), false, "builtin", false);
        taintConfig.load(new ByteArrayInputStream(config.getBytes(StandardCharsets.UTF_8)), false, "custom", true);
        taintConfig.load(new ByteArrayInputStream(config.getBytes(StandardCharsets.UTF_8)), false, "custom2", true);

        assertEquals(taintConfig.getExcludedEntries(), 4);
        assertEquals(taintConfig.getExcludedMatches(), 2);
        assertTrue(taintConfig.get("testcode/A.excluded()Ljava/lang/String;").getOutputTaint().isTainted());
        assertTrue(taintConfig.containsKey("testcode/A.kept()Ljava/lang/String;"));

        StringWriter writer = new StringWriter();
        usage.write(taintConfig, writer);
        String output = writer.toString();
        assertTrue(output.contains("usage\ttestcode/A.kept()Ljava/lang/String;\tM\t1,2\t"), output);
        assertTrue(output.contains("usage\ttestcode/A.lookup(\"y\")@testcode/B\tL\t"), output);
        assertFalse(output.contains("testcode/A.lookup(\"x\")"), output);
        assertFalse(output.contains("usage\ttestcode/A.excluded()"), output);
    }
}
