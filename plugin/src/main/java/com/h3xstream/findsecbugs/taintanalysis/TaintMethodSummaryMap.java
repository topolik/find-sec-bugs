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

import com.h3xstream.findsecbugs.taintanalysis.methodsummary.TaintMethodSummaryParser;
import com.h3xstream.findsecbugs.taintanalysis.methodsummary.WithArgumentsCount;
import com.h3xstream.findsecbugs.taintanalysis.methodsummary.WithFullMethodDescription;
import com.h3xstream.findsecbugs.taintanalysis.methodsummary.WithMethodWildcard;
import com.h3xstream.findsecbugs.taintanalysis.methodsummary.WithReturnTypeOnly;
import com.h3xstream.findsecbugs.taintanalysis.methodsummary.WithSignatureWildcard;
import com.h3xstream.findsecbugs.taintanalysis.methodsummary.WithStringArgument;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.TreeSet;

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
    private static final List<TaintMethodSummaryParser> METHOD_SUMMARY_PARSERS;
    static {
        METHOD_SUMMARY_PARSERS = new ArrayList<TaintMethodSummaryParser>(6);
        METHOD_SUMMARY_PARSERS.add(new WithStringArgument());
        METHOD_SUMMARY_PARSERS.add(new WithFullMethodDescription());
        METHOD_SUMMARY_PARSERS.add(new WithArgumentsCount());
        METHOD_SUMMARY_PARSERS.add(new WithSignatureWildcard());
        METHOD_SUMMARY_PARSERS.add(new WithMethodWildcard());
        METHOD_SUMMARY_PARSERS.add(new WithReturnTypeOnly());
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

    public TaintMethodSummary getMethodSummary(String className, String methodName, String signature, TaintFrameModelingVisitor taintFrameModelingVisitor) {
        for (TaintMethodSummaryParser parser : METHOD_SUMMARY_PARSERS) {
            String key = parser.parse(className, methodName, signature, taintFrameModelingVisitor);
            if (key == null || key.isEmpty()) {
                continue;
            }

            TaintMethodSummary summary = get(key);
            if (summary != null) {
                return summary;
            }
        }

        return null;
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
                for(TaintMethodSummaryParser parser : METHOD_SUMMARY_PARSERS) {
                    matches = matches || parser.accepts(fullMethod);
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
