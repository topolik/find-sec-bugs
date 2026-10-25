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

import java.io.File;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.spy;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class TaintConfigUsageTest extends BaseDetectorTest {

    private static final String PACKAGE = "testcode/taint/configusage/";

    @Test
    public void verdicts() throws Exception {
        URL configUrl = this.getClass().getResource("/com/h3xstream/findsecbugs/taintanalysis/ConfigUsage.txt");
        File configFile = new File(configUrl.toURI());
        File usageFile = File.createTempFile("config-usage", ".txt");

        FindSecBugsGlobalConfig config = FindSecBugsGlobalConfig.getInstance();
        try {
            config.setCustomConfigFile(configFile.getCanonicalPath());
            config.setTaintConfigUsage("all");
            config.setTaintConfigUsageFile(usageFile.getAbsolutePath());

            String[] files = {
                    getClassFilePath(PACKAGE + "ConfigUsageSamples"),
                    getClassFilePath(PACKAGE + "ConfigUsageService"),
                    getClassFilePath(PACKAGE + "ConfigUsageBase"),
                    getClassFilePath(PACKAGE + "ConfigUsageChild")
            };

            EasyBugReporter reporter = spy(new SecurityReporter());
            analyze(files, reporter);

            List<String> lines = Files.readAllLines(usageFile.toPath(), StandardCharsets.UTF_8);
            assertTrue(lines.get(0).startsWith("# config-usage v1 mode=all failures=0"), lines.get(0));

            Map<String, String[]> usages = new HashMap<String, String[]>();
            Map<String, String[]> overrides = new HashMap<String, String[]>();
            for (String line : lines) {
                String[] columns = line.split("\t", -1);
                if ("usage".equals(columns[0])) {
                    assertEquals(columns.length, 11, line);
                    usages.put(columns[1], columns);
                } else if ("override".equals(columns[0])) {
                    overrides.put(columns[1], columns);
                }
            }

            assertVerdict(usages, PACKAGE + "ConfigUsageSamples.neverCalled()Ljava/lang/String;", "unused", 0);
            assertVerdict(usages, PACKAGE + "ConfigUsageSamples.constant()Ljava/lang/String;", "redundant-derived", 1);
            assertVerdict(usages, PACKAGE + "ConfigUsageSamples.number(Ljava/lang/String;)Ljava/lang/Integer;",
                    "redundant-type", 1);
            // SAFE_CONFIG of the safe return type would also taint the mutable list argument
            assertVerdict(usages, PACKAGE + "ConfigUsageSamples.count(Ljava/util/List;)Ljava/lang/Integer;",
                    "differs", 1);
            assertVerdict(usages, PACKAGE + "ConfigUsageSamples.echo(Ljava/lang/String;)Ljava/lang/String;",
                    "conditional", 1);
            assertVerdict(usages, PACKAGE + "ConfigUsageSamples.parameter(Ljavax/servlet/http/HttpServletRequest;)Ljava/lang/String;",
                    "assertion", 1);
            assertVerdict(usages, PACKAGE + "ConfigUsageService.getName()Ljava/lang/String;", "effective", 1);

            // inherited method is attributed to the entry of the parent
            assertVerdict(usages, PACKAGE + "ConfigUsageBase.label()Ljava/lang/String;", "effective", 1);
            assertFalse(usages.containsKey(PACKAGE + "ConfigUsageChild.label()Ljava/lang/String;"));

            String[] location = usages.get(PACKAGE + "ConfigUsageService.lookup(\"safe\")@" + PACKAGE + "ConfigUsageSamples");
            assertTrue(location != null, "location entry " + usages.keySet());
            assertEquals(location[2], "L");
            assertEquals(location[4], "1");
            assertEquals(location[8], "effective");

            // custom entry hides the built-in source
            String[] queryString = usages.get("javax/servlet/http/HttpServletRequest.getQueryString()Ljava/lang/String;");
            assertEquals(queryString[8], "assertion");
            assertTrue(queryString[6].startsWith("config-builtin/unsafe"), queryString[6]);

            assertEquals(usages.get("Ltestcode/taint/configusage/ConfigUsageUnrelated;")[8], "untracked");

            assertEquals(overrides.get("javax/servlet/http/HttpServletRequest.getQueryString()Ljava/lang/String;")[7],
                    "weaken-builtin");
            assertEquals(overrides.get("java/lang/Integer.toString()Ljava/lang/String;")[7], "same");
        } finally {
            config.setCustomConfigFile("");
            config.setTaintConfigUsage(null);
            config.setTaintConfigUsageFile("config-usage.txt");
            usageFile.delete();
        }
    }

    private static void assertVerdict(Map<String, String[]> usages, String key, String verdict, int hits) {
        String[] columns = usages.get(key);
        assertTrue(columns != null, key + " missing in " + usages.keySet());
        assertEquals(columns[8], verdict, String.join("\t", columns));
        assertEquals(Integer.parseInt(columns[4]), hits, String.join("\t", columns));
    }
}
