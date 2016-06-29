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

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * Map of taint summaries for all known methods
 *
 * This class extends HashMap:
 * <ul>
 *  <li>The key is the method signature (ie :
 org/hibernate/Session.createQuery(Ljava/lang/String;)Lorg/hibernate/Query;)</li>
 *  <li>The value is the behavior of the method
 *  ("0" for param index 0 is tainted,
 *  "UNKNOWN" if the method does not become tainted base on the value,
 *  "TAINTED" if the result must be consider unsafe)</li>
 * </ul>
 *
 * @author David Formanek (Y Soft Corporation, a.s.)
 */
public class TaintMethodSummaryMap extends HashMap<String, TaintMethodSummary> {
    
    private static final long serialVersionUID = 1L;
    private static final List<Pattern> allowedMethodPatterns = new ArrayList<Pattern>();

    static {
        String classWithPackageRegex = "([a-z][a-z0-9]*\\/)*[A-Z][a-zA-Z0-9\\$]*";
        String typeRegex = "(\\[)*((L" + classWithPackageRegex + ";)|B|C|D|F|I|J|S|Z)";
        String returnRegex = "(V|(" + typeRegex + "))";
        String methodRegex = "(([a-zA-Z][a-zA-Z0-9]*)|(<init>))";
        String signatureRegex = "\\((" + typeRegex + ")*\\)" + returnRegex;

        // javax/servlet/http/HttpServletRequest.getAttribute("applicationConstant")@org/apache/jsp/edit_jsp.java
        // javax/servlet/http/HttpServletRequest.getAttribute(SAFE)@*
        String methodWithStringArgumentsTheArgumentRegex = "\"[^\"]*\"";
        String methodWithStringArgumentsTaintArgumentRegex = "(TAINTED|UNKNOWN|SAFE)";
        String methodWithStringArgumentsSignatureRegex = "\\((" + methodWithStringArgumentsTheArgumentRegex + ",?|" + methodWithStringArgumentsTaintArgumentRegex + ",?)+\\)";
        String methodWithStringArgumentsLocation = "@(\\*|.+)";
        String methodWithStringArgumentsRegex = classWithPackageRegex + "\\." + methodRegex + methodWithStringArgumentsSignatureRegex + methodWithStringArgumentsLocation;
        allowedMethodPatterns.add(Pattern.compile(methodWithStringArgumentsRegex));

        // java/lang/String.valueOf(Z)Ljava/lang/String;
        String fullMethodNameRegex = classWithPackageRegex + "\\." + methodRegex + signatureRegex;
        allowedMethodPatterns.add(Pattern.compile(fullMethodNameRegex));

        // java/lang/String.valueOf(1)Ljava/lang/String;
        String methodWithArgumentCountSignatureRegex =  "\\([0-9]+\\)";
        String methodWithArgumentCountRegex = classWithPackageRegex + "\\." + methodRegex + methodWithArgumentCountSignatureRegex  + returnRegex;
        allowedMethodPatterns.add(Pattern.compile(methodWithArgumentCountRegex));

        // java/sql/ResultSet.getString(*)*
        String methodWildardsWithClassAndMethodRegex = classWithPackageRegex + "\\." + methodRegex + Pattern.quote("(*)*");
        allowedMethodPatterns.add(Pattern.compile(methodWildardsWithClassAndMethodRegex));

        // com/company/Constants.*(*)*
        String methodWildcardsWithClassNameRegex = classWithPackageRegex + Pattern.quote(".*(*)*");
        allowedMethodPatterns.add(Pattern.compile(methodWildcardsWithClassNameRegex));

        // *.*(*)Lcom/company/ConstantEnum;:SAFE
        String methodWildcardsWithReturnTypeRegex = Pattern.quote("*.*(*)") + returnRegex;
        allowedMethodPatterns.add(Pattern.compile(methodWildcardsWithReturnTypeRegex));

        // cast: (Lcom/company/ConstantEnum;):SAFE
        String classCastRegex = "\\(" + typeRegex + "\\)";
        allowedMethodPatterns.add(Pattern.compile(classCastRegex));
    }

    /**
     * Dumps all the summaries for debugging
     * 
     * @param output stream where to output the summaries
     */
    public void dump(PrintStream output) {
        TreeSet<String> keys = new TreeSet<String>(keySet());
        for (String key : keys) {
            output.println(key + ":" + get(key));
        }
    }

    /**
     * Loads method summaries from stream checking the format
     * 
     * @param input input stream of configured summaries
     * @param checkRewrite whether to check duplicit summaries
     * @throws IOException if cannot read the stream or the format is bad
     * @throws IllegalArgumentException for bad method format
     * @throws IllegalStateException if there are duplicit configurations
     */
    public void load(InputStream input, final boolean checkRewrite) throws IOException {
        new TaintMethodSummaryMapLoader().load(input, new TaintMethodSummaryMapLoader.TaintMethodSummaryReceiver() {
            @Override
            public void receiveTaintMethodSummary(String fullMethod, TaintMethodSummary taintMethodSummary) {
                boolean matches = false;
                for (Pattern pattern : allowedMethodPatterns) {
                    matches = matches || pattern.matcher(fullMethod).matches();
                }
                if (!matches) {
                    throw new IllegalArgumentException("Invalid full method name " + fullMethod + " configured");
                }
                if (checkRewrite && containsKey(fullMethod)) {
                    throw new IllegalStateException("Summary for " + fullMethod + " already loaded");
                }
                put(fullMethod, taintMethodSummary);
            }
        });
    }
}
