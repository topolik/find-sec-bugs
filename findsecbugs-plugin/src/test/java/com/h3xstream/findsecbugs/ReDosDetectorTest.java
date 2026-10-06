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
package com.h3xstream.findsecbugs;

import com.h3xstream.findbugs.test.BaseDetectorTest;
import com.h3xstream.findbugs.test.EasyBugReporter;
import org.testng.annotations.Test;

import java.util.Arrays;

import static org.mockito.Mockito.*;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class ReDosDetectorTest extends BaseDetectorTest {

    //Reusable matcher for REDOS bug

    @Test
    public void analyseSafePattern() {

        RegexRedosAnalyzer analyzer = new RegexRedosAnalyzer();
        analyzer.analyseRegexString("");
        analyzer.analyseRegexString("[a-zA-Z]+[0-9]*");
        analyzer.analyseRegexString("(id-[0-9]+)-([0-9A-F]*)");
        analyzer.analyseRegexString("(\\w+)\\s+in\\s+\\(('[^']*'(?:\\s*,\\s*'[^']*')*)\\)");
        analyzer.analyseRegexString("(<[^>]*>)+");
        analyzer.analyseRegexString("[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+)*");
        analyzer.analyseRegexString("[A-Za-z_][A-Za-z0-9_]*(?:[./][A-Za-z_][A-Za-z0-9_]*)*");

        assertFalse(analyzer.isVulnerable(),"False positive detected!");
    }

    @Test
    public void analyseUndelimitedRunPattern() {
        RegexRedosAnalyzer analyzer = new RegexRedosAnalyzer();
        analyzer.analyseRegexString("([^']*,)+");
        assertTrue(analyzer.isVulnerable(),"([^']*,)+ should be detect as REDOS");
    }

    @Test
    public void analyseOverlappingSeparatorPattern() {
        RegexRedosAnalyzer analyzer = new RegexRedosAnalyzer();
        analyzer.analyseRegexString("(\\.[a-z.]+)+");
        assertTrue(analyzer.isVulnerable(),"(\\.[a-z.]+)+ should be detect as REDOS");

        analyzer = new RegexRedosAnalyzer();
        analyzer.analyseRegexString("(?:,\\w[a-z]+)*");
        assertTrue(analyzer.isVulnerable(),"(?:,\\w[a-z]+)* should be detect as REDOS");

        analyzer = new RegexRedosAnalyzer();
        analyzer.analyseRegexString("((ab)+)+");
        assertTrue(analyzer.isVulnerable(),"((ab)+)+ should be detect as REDOS");
    }

    @Test
    public void analyseSuspectPattern() {
        RegexRedosAnalyzer analyzer = new RegexRedosAnalyzer();
        analyzer.analyseRegexString("((a)+)+");
        assertTrue(analyzer.isVulnerable(),"((a)+)+ should be detect as REDOS");

        analyzer = new RegexRedosAnalyzer();
        analyzer.analyseRegexString("([b-d])(([a]*))+(0-9)");
        assertTrue(analyzer.isVulnerable(),"([b-d])(([a]*))+(0-9) should be detect as REDOS");
    }

    /**
     * Test that utilize compile code.
     *
     * @throws Exception
     */
    @Test
    public void detectRedosInCode() throws Exception {
        //Locate test code
        String[] files = {
                getClassFilePath("testcode/VariousRedos")
        };

        //Run the analysis
        EasyBugReporter reporter = spy(new SecurityReporter());
        analyze(files, reporter);

        //Field with a Pattern initialize on instantiation

        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("REDOS")
                        .inClass("VariousRedos").atLine(8)
                        .build()
        );

        //Pattern build in methods
        for (Integer line : Arrays.asList(16, 26)) {
            verify(reporter).doReportBug(
                    bugDefinition()
                            .bugType("REDOS")
                            .inClass("VariousRedos").inMethod("main").atLine(line)
                            .build()
            );
        }
    }


    @Test
    public void detectRedosInAnnotation() throws Exception {
        //Locate test code
        String[] files = {
                getClassFilePath("testcode/RedosInPatternAnnotation.java")
        };

        //Run the analysis
        EasyBugReporter reporter = spy(new SecurityReporter());
        analyze(files, reporter);

        //Field with a Pattern initialize on instantiation

        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("REDOS")
                        .inClass("RedosInPatternAnnotation")
                        .atField("email")
                        .build()
        );
    }

    @Test
    public void detectJakartaRedosInAnnotation() throws Exception {
        //Locate test code
        String[] files = {
                getClassFilePath("testcode/JakartaRedosInPatternAnnotation.java")
        };

        //Run the analysis
        EasyBugReporter reporter = spy(new SecurityReporter());
        analyze(files, reporter);

        //Field with a Pattern initialize on instantiation
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("REDOS")
                        .inClass("JakartaRedosInPatternAnnotation")
                        .atField("email")
                        .build()
        );
    }

}
