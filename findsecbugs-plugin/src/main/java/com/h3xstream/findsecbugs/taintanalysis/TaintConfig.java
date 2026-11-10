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

import com.h3xstream.findsecbugs.BCELUtil;
import edu.umd.cs.findbugs.ba.AnalysisContext;
import edu.umd.cs.findbugs.ba.DataflowAnalysisException;
import edu.umd.cs.findbugs.ba.SignatureParser;
import edu.umd.cs.findbugs.classfile.MethodDescriptor;
import org.apache.bcel.Repository;
import org.apache.bcel.classfile.AnnotationEntry;
import org.apache.bcel.classfile.JavaClass;
import org.apache.bcel.classfile.Method;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Map of taint summaries for all known methods and classes
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
public class TaintConfig extends HashMap<String, TaintMethodConfig> {

    private static final long serialVersionUID = 1L;
    private final Map<String, TaintClassConfig> taintClassConfigMap = new HashMap<String, TaintClassConfig>();
    private final Map<String, TaintFieldConfig> taintFieldConfigMap = new HashMap<String, TaintFieldConfig>();
    private final Map<String, TaintMethodConfigWithArgumentsAndLocation> taintMethodConfigWithArgumentsAndLocationMap =
            new HashMap<String, TaintMethodConfigWithArgumentsAndLocation>();

    private final Map<String, Taint> staticFieldsTaint = new HashMap<String, Taint>();

    /**
     * Annotation type signatures (e.g. Lcom/liferay/portal/kernel/bean/AutoEscape;)
     * whose unconfigured instance methods return the receiver's taint, tags
     * included. Configured with a line {@code @com/liferay/portal/kernel/bean/AutoEscape:RECEIVER}.
     */
    private final Set<String> receiverTransferAnnotations = new HashSet<String>();
    private final Map<String, Boolean> receiverTransferMethodCache = new ConcurrentHashMap<String, Boolean>();

    private transient TaintConfigUsage usage;
    private transient Set<String> excludedKeys = Collections.emptySet();
    private final Set<String> excludedMatches = new HashSet<String>();
    private int excludedEntries;

    private static final Pattern DERIVED_PARAMETER_TAGS = Pattern.compile("(\\d+)\\[([^\\]]*)\\]");
    private int importedEntries;
    private int importSkippedEntries;
    private int importPresentEntries;
    private int importBadEntries;

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
     * Loads summaries from stream checking the format
     * 
     * @param input input stream of configured summaries
     * @param checkRewrite whether to check duplicit summaries
     * @throws IOException if cannot read the stream or the format is bad
     * @throws IllegalArgumentException for bad method format
     * @throws IllegalStateException if there are duplicit configurations
     */
    public void load(InputStream input, final boolean checkRewrite) throws IOException {
        load(input, checkRewrite, null, false);
    }

    /**
     * Loads summaries from stream checking the format
     *
     * @param input input stream of configured summaries
     * @param checkRewrite whether to check duplicit summaries
     * @param source resource name or path of the config, for the usage accounting
     * @param custom whether the config is custom, for the usage accounting
     * @throws IOException if cannot read the stream or the format is bad
     * @throws IllegalArgumentException for bad method format
     * @throws IllegalStateException if there are duplicit configurations
     */
    public void load(InputStream input, final boolean checkRewrite, String source, boolean custom) throws IOException {
        final int sourceId = usage == null ? -1 : usage.addSource(source, custom);
        new TaintConfigLoader().load(input, new TaintConfigLoader.TaintConfigReceiver() {
            @Override
            public void receiveTaintConfig(String typeSignature, String config) throws IOException {
                if (custom && isExcluded(typeSignature)) {
                    return;
                }
                if (typeSignature.startsWith("@")) {
                    if (!"RECEIVER".equals(config.trim())) {
                        throw new IllegalArgumentException("Invalid annotation config " + typeSignature + ":" + config);
                    }
                    receiverTransferAnnotations.add("L" + typeSignature.substring(1) + ";");
                    receiverTransferMethodCache.clear();
                    if (usage != null) {
                        usage.recordOther(typeSignature, 'A', sourceId, config.trim());
                    }
                    return;
                }

                if (TaintMethodConfig.accepts(typeSignature, config)) {
                    if (checkRewrite && containsKey(typeSignature)) {
                        throw new IllegalStateException("Config for " + typeSignature + " already loaded");
                    }
                    TaintMethodConfig taintMethodConfig = new TaintMethodConfig(true).load(config);
                    taintMethodConfig.setTypeSignature(typeSignature);
                    TaintMethodConfig previous = put(typeSignature, taintMethodConfig);
                    if (usage != null) {
                        usage.recordMethod(typeSignature, 'M', sourceId, previous, taintMethodConfig);
                    }
                    return;
                }

                if (TaintClassConfig.accepts(typeSignature, config)) {
                    if (checkRewrite && taintClassConfigMap.containsKey(typeSignature)) {
                        throw new IllegalStateException("Config for " + typeSignature + " already loaded");
                    }
                    TaintClassConfig taintClassConfig = new TaintClassConfig().load(config);
                    taintClassConfig.setTypeSignature(typeSignature);
                    taintClassConfigMap.put(typeSignature, taintClassConfig);
                    if (usage != null) {
                        usage.recordOther(typeSignature, 'C', sourceId, config);
                    }
                    return;
                }

                if (TaintFieldConfig.accepts(typeSignature, config)) {
                    if (checkRewrite && taintFieldConfigMap.containsKey(typeSignature)) {
                        throw new IllegalStateException("Config for " + typeSignature + " already loaded");
                    }
                    TaintFieldConfig taintFieldConfig = new TaintFieldConfig().load(config);
                    taintFieldConfig.setTypeSignature(typeSignature);
                    taintFieldConfigMap.put(typeSignature, taintFieldConfig);
                    if (usage != null) {
                        usage.recordOther(typeSignature, 'F', sourceId, config);
                    }
                    return;
                }

                if (TaintMethodConfigWithArgumentsAndLocation.accepts(typeSignature, config)) {
                    if (checkRewrite && taintMethodConfigWithArgumentsAndLocationMap.containsKey(typeSignature)) {
                        throw new IllegalStateException("Config for " + typeSignature + " already loaded");
                    }

                    TaintMethodConfigWithArgumentsAndLocation methodConfig =
                            new TaintMethodConfigWithArgumentsAndLocation().load(config);

                    methodConfig.setTypeSignature(typeSignature);

                    String key = typeSignature + '@' + methodConfig.getLocation();
                    if (custom && isExcluded(key)) {
                        return;
                    }
                    TaintMethodConfig previous = taintMethodConfigWithArgumentsAndLocationMap.put(key, methodConfig);
                    if (usage != null) {
                        usage.recordMethod(key, 'L', sourceId, previous, methodConfig);
                    }
                    return;
                }

                throw new IllegalArgumentException("Invalid signature " + typeSignature + " configured");
            }
        });
    }


    /**
     * Imports the summaries derived by the analysis of other classes, the lines of derived-config.txt
     * {@code signature[:output taint](^stack index:argument output taint)*}. A summary is added as not configured,
     * only if no summary is set for the method and its class is not skipped.
     *
     * @param input stream of the derived summaries
     * @param skipClass tells whether to skip the summaries of the slashed class name, e.g. of the analyzed classes
     * @throws IOException if cannot read the stream
     */
    public void loadDerived(InputStream input, Predicate<String> skipClass) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8));
        String line;
        while ((line = reader.readLine()) != null) {
            line = line.trim();
            if (line.isEmpty()) {
                continue;
            }
            String[] parts = line.split("\\^");
            int index = parts[0].indexOf(':');
            String key = index < 0 ? parts[0] : parts[0].substring(0, index);
            int parenthesis = key.indexOf('(');
            int dot = parenthesis < 0 ? -1 : key.lastIndexOf('.', parenthesis);
            if (dot <= 0) {
                importBadEntries++;
                continue;
            }
            if (skipClass.test(key.substring(0, dot))) {
                importSkippedEntries++;
                continue;
            }
            if (containsKey(key)) {
                importPresentEntries++;
                continue;
            }
            try {
                TaintMethodConfig config = new TaintMethodConfig(false);
                if (index >= 0) {
                    config.setOuputTaint(loadDerivedTaint(parts[0].substring(index + 1)));
                }
                for (int i = 1; i < parts.length; i++) {
                    String[] tuple = parts[i].split(":", 2);
                    if (tuple.length != 2) {
                        throw new IOException("Bad format: argument output taint " + parts[i]);
                    }
                    config.setParameterOutputTaint(Integer.parseInt(tuple[0]), loadDerivedTaint(tuple[1]));
                }
                config.setParametersOutputTaintsProcessed(true);
                config.setTypeSignature(key);
                put(key, config);
                importedEntries++;
            } catch (IOException | RuntimeException ex) {
                importBadEntries++;
            }
        }
    }

    private static Taint loadDerivedTaint(String str) throws IOException {
        Map<Integer, Set<TaintTag>> parameterTags = new HashMap<Integer, Set<TaintTag>>();
        Matcher matcher = DERIVED_PARAMETER_TAGS.matcher(str);
        StringBuffer sb = new StringBuffer();
        while (matcher.find()) {
            Set<TaintTag> tags = new HashSet<TaintTag>();
            for (String tagName : matcher.group(2).split(",")) {
                if (!tagName.isEmpty()) {
                    TaintTag tag = TaintTag.get(tagName);
                    tags.add(tag == null ? TaintTag.create(tagName) : tag);
                }
            }
            parameterTags.put(Integer.valueOf(matcher.group(1)), tags);
            matcher.appendReplacement(sb, matcher.group(1));
        }
        matcher.appendTail(sb);
        // the tags of the taint apply to its arguments too, the arguments with other tags are set afterwards
        Taint taint = new TaintMethodConfig(false).load(sb.toString()).getOutputTaint();
        for (Map.Entry<Integer, Set<TaintTag>> entry : parameterTags.entrySet()) {
            taint.setParameterTags(entry.getKey(), entry.getValue());
        }
        return taint;
    }

    /**
     * @return number of imported derived summaries
     */
    public int getImportedEntries() {
        return importedEntries;
    }

    /**
     * @return number of derived summaries not imported because their class is skipped
     */
    public int getImportSkippedEntries() {
        return importSkippedEntries;
    }

    /**
     * @return number of derived summaries not imported because a summary is already set
     */
    public int getImportPresentEntries() {
        return importPresentEntries;
    }

    /**
     * @return number of derived summaries not imported because of a bad format
     */
    public int getImportBadEntries() {
        return importBadEntries;
    }

    private boolean isExcluded(String key) {
        if (!excludedKeys.contains(key)) {
            return false;
        }
        excludedEntries++;
        excludedMatches.add(key);
        return true;
    }

    /**
     * Drops the given keys from the custom configs loaded afterwards, location entries are matched
     * by the signature followed by @ and the location
     */
    public void setExcludedKeys(Set<String> excludedKeys) {
        this.excludedKeys = excludedKeys;
    }

    /**
     * @return number of custom entries dropped by the excluded keys
     */
    public int getExcludedEntries() {
        return excludedEntries;
    }

    /**
     * @return number of excluded keys that matched a custom entry
     */
    public int getExcludedMatches() {
        return excludedMatches.size();
    }

    public TaintConfigUsage getUsage() {
        return usage;
    }

    /**
     * Enables the usage accounting of the summaries loaded afterwards
     */
    public void setUsage(TaintConfigUsage usage) {
        this.usage = usage;
    }

    public boolean isClassImmutable(String typeSignature) {
        if (!isClassType(typeSignature)) {
            return false;
        }

        TaintClassConfig classConfig = taintClassConfigMap.get(typeSignature);
        if (classConfig == null) {
            return false;
        }

        return classConfig.isImmutable();
    }

    public boolean isClassTaintSafe(String typeSignature) {
        if (typeSignature != null && typeSignature.startsWith("[")) {
            // an array can only hold instances of its element type
            return isClassTaintSafe(typeSignature.substring(1));
        }
        if (!isClassType(typeSignature)) {
            return false;
        }

        TaintClassConfig taintClassConfig = getTaintClassConfig(typeSignature);
        if (taintClassConfig == null) {
            return false;
        }

        return taintClassConfig.getTaintState().equals(Taint.State.SAFE);
    }

    public Taint.State getClassTaintState(String typeSignature, Taint.State defaultState) {
        if (!isClassType(typeSignature)) {
            return defaultState;
        }

        TaintClassConfig taintClassConfig = getTaintClassConfig(typeSignature);

        if (taintClassConfig == null) {
            return defaultState;
        }

        Taint.State taintClassConfigState = taintClassConfig.getTaintState();

        if (taintClassConfigState.equals(TaintClassConfig.DEFAULT_TAINT_STATE)) {
            return defaultState;
        }

        return taintClassConfigState;
    }

    public Taint.State getFieldTaintState(String fieldSignature, Taint.State defaultState) {
        if (!isFieldType(fieldSignature)) {
            return defaultState;
        }

        TaintFieldConfig taintFieldConfig = taintFieldConfigMap.get(fieldSignature);

        if (taintFieldConfig == null) {
            return defaultState;
        }

        Taint.State taintFieldConfigState = taintFieldConfig.getTaintState();

        if (taintFieldConfigState.equals(TaintClassConfig.DEFAULT_TAINT_STATE)) {
            return defaultState;
        }

        return taintFieldConfigState;
    }

    public TaintClassConfig getTaintClassConfig(String typeSignature) {
        if (!isClassType(typeSignature)) {
            return null;
        }

        return taintClassConfigMap.get(typeSignature);
    }

    private boolean isClassType(String typeSignature) {
        return typeSignature != null && typeSignature.length() > 2 && typeSignature.charAt(0) == 'L';
    }

    private boolean isFieldType(String typeSignature) {
        return typeSignature != null && typeSignature.length() > 2 && typeSignature.charAt(0) != 'L';
    }

    /**
     * Ignores safe primitive parameters except for char, which is not
     * inherently safe.
     */
    private static int[] getParameterSlots(SignatureParser p) {
        String[] parameters = p.getArguments();
        int[] pnums = new int[parameters.length];
        int count = 0;
        for (int i = 0; i < parameters.length; i++) {
            String parameter = parameters[i];
            if (SignatureParser.isReferenceType(parameter) || "C".equals(parameter)) {
                pnums[count++] = p.getSlotsFromTopOfStackForParameter(i);
            }
        }

        return (count == parameters.length) ? pnums : Arrays.copyOfRange(pnums, 0, count);
    }

    public TaintMethodConfig getMethodConfig(TaintFrame frame, MethodDescriptor methodDescriptor, String className, String methodId) {
        TaintMethodConfig taintMethodConfig = getTaintMethodConfigWithArgumentsAndLocation(frame, methodDescriptor, className, methodId);

        if (taintMethodConfig == null) {
            taintMethodConfig = get(className.concat(methodId));
        }

        if (taintMethodConfig == null) {
            taintMethodConfig = getSuperMethodConfig(className, methodId);
        }

        // In Java 9+, string concatenation is done with invokedynamic
        // that takes a String constant and substitues one or more
        // values into placeholders. There is no StringBuilder on the
        // stack with mutable taint state.
        if (taintMethodConfig == null && methodId.indexOf("makeConcatWithConstants") > 0) {
            taintMethodConfig = new TaintMethodConfig(true);
            Taint t = new Taint(Taint.State.UNKNOWN);
            String signature = methodId.substring(methodId.indexOf("("), methodId.length());
            SignatureParser p = new SignatureParser(signature);
            for (int paramNum : getParameterSlots(p)) {
                t.addParameter(paramNum);
            }
            // If we had only safe parameters (int, long, etc.), the combined String is SAFE.
            taintMethodConfig.setOuputTaint(t.hasParameters() ? t : new Taint(Taint.State.SAFE));
        }

        return taintMethodConfig;
    }

    public TaintMethodConfig getSuperMethodConfig(String className, String methodId) {
        try {
            if (className.endsWith("]")) {
                // not a real class
                return null;
            }

            JavaClass javaClass = Repository.lookupClass(className);
            assert javaClass != null;

            Set<String> parentClassNames = BCELUtil.getParentClassNames(javaClass);

            for (String parentClassName : parentClassNames) {
                TaintMethodConfig conf = get(parentClassName.concat(methodId));
                if (conf != null) {
                    return conf;
                }
            }

        } catch (ClassNotFoundException ex) {
            AnalysisContext.reportMissingClass(ex);
        }

        return null;
    }

    /**
     * Returns the supertypes in the order {@link #getSuperMethodConfig(String, String)} visits them,
     * without reporting missing classes
     *
     * @param className slashed name of the class
     * @return supertype names, empty for arrays and missing classes
     */
    public List<String> getParentClassNamesQuietly(String className) {
        if (className.endsWith("]")) {
            return Collections.emptyList();
        }
        try {
            return new ArrayList<String>(BCELUtil.getParentClassNamesQuietly(Repository.lookupClass(className)));
        } catch (ClassNotFoundException ex) {
            return Collections.emptyList();
        }
    }

    /**
     * Whether {@link #getSuperMethodConfig(String, String)} finds a summary, without reporting missing classes
     */
    public boolean hasSuperMethodConfigQuietly(String className, String methodId) {
        for (String parentClassName : getParentClassNamesQuietly(className)) {
            if (containsKey(parentClassName.concat(methodId))) {
                return true;
            }
        }
        return false;
    }

    /**
     * Same as {@link #isReceiverTransferMethod(String, String)} without reporting missing classes
     * and without caching the result
     */
    public boolean isReceiverTransferMethodQuietly(String className, String methodId) {
        if (receiverTransferAnnotations.isEmpty() || className.endsWith("]")) {
            return false;
        }

        Boolean result = receiverTransferMethodCache.get(className.concat(methodId));
        if (result != null) {
            return result;
        }
        int signatureIndex = methodId.indexOf('(');
        String methodName = methodId.substring(1, signatureIndex);
        String signature = methodId.substring(signatureIndex);
        try {
            JavaClass javaClass = Repository.lookupClass(className);
            if (hasReceiverTransferAnnotation(javaClass, methodName, signature)) {
                return true;
            }
            for (String parentClassName : BCELUtil.getParentClassNamesQuietly(javaClass)) {
                try {
                    if (hasReceiverTransferAnnotation(Repository.lookupClass(parentClassName), methodName, signature)) {
                        return true;
                    }
                } catch (ClassNotFoundException ex) {
                    // ignore
                }
            }
        } catch (ClassNotFoundException ex) {
            // ignore
        }
        return false;
    }

    /**
     * Whether the method, declared in the class or any of its supertypes, carries
     * one of the annotations configured with {@code @annotation/Type:RECEIVER}
     *
     * @param className slashed name of the invoked class
     * @param methodId method name with signature, e.g. .getName()Ljava/lang/String;
     */
    public boolean isReceiverTransferMethod(String className, String methodId) {
        if (receiverTransferAnnotations.isEmpty() || className.endsWith("]")) {
            return false;
        }

        String key = className.concat(methodId);
        Boolean result = receiverTransferMethodCache.get(key);
        if (result == null) {
            result = hasReceiverTransferAnnotation(className, methodId);
            receiverTransferMethodCache.put(key, result);
        }
        return result;
    }

    private boolean hasReceiverTransferAnnotation(String className, String methodId) {
        int signatureIndex = methodId.indexOf('(');
        String methodName = methodId.substring(1, signatureIndex);
        String signature = methodId.substring(signatureIndex);
        try {
            JavaClass javaClass = Repository.lookupClass(className);
            if (hasReceiverTransferAnnotation(javaClass, methodName, signature)) {
                return true;
            }
            for (String parentClassName : BCELUtil.getParentClassNames(javaClass)) {
                try {
                    if (hasReceiverTransferAnnotation(Repository.lookupClass(parentClassName), methodName, signature)) {
                        return true;
                    }
                } catch (ClassNotFoundException ex) {
                    AnalysisContext.reportMissingClass(ex);
                }
            }
        } catch (ClassNotFoundException ex) {
            AnalysisContext.reportMissingClass(ex);
        }
        return false;
    }

    private boolean hasReceiverTransferAnnotation(JavaClass javaClass, String methodName, String signature) {
        for (Method method : javaClass.getMethods()) {
            if (method.isStatic() || !method.getName().equals(methodName) || !method.getSignature().equals(signature)) {
                continue;
            }
            for (AnnotationEntry annotationEntry : method.getAnnotationEntries()) {
                if (receiverTransferAnnotations.contains(annotationEntry.getAnnotationType())) {
                    return true;
                }
            }
        }
        return false;
    }

    private TaintMethodConfig getTaintMethodConfigWithArgumentsAndLocation(TaintFrame frame, MethodDescriptor methodDescriptor, String className, String methodId) {
        if (taintMethodConfigWithArgumentsAndLocationMap.isEmpty()) {
            return null;
        }

        String signature = methodId.substring(methodId.indexOf("("), methodId.length());
        int parameters = new SignatureParser(signature).getNumParameters();
        StringBuffer sb = null;
        if (parameters > 0 && frame.getStackDepth() >= parameters) {
            sb = new StringBuffer(parameters);
            for (int i = parameters - 1; i >= 0; i--) {
                try {
                    Taint taint = frame.getStackValue(i);
                    String value = taint.getConstantValue();
                    if (value != null) {
                        sb.append('"' + value + '"');
                    }
                    else {
                        sb.append(taint.getState().name());
                    }
                    if (i > 0) {
                        sb.append(',');
                    }
                }
                catch (DataflowAnalysisException e) {
                    assert false : e.getMessage();
                }
            }
        }

        String arguments = sb != null ? sb.toString() : "";
        String methodName = methodId.substring(1, methodId.indexOf('('));
        String methodDefinition = className + "." + methodName + "(" + arguments + ")";
        String key = methodDefinition + "@" + methodDescriptor.getSlashedClassName();
        return taintMethodConfigWithArgumentsAndLocationMap.get(key);
    }

    public Taint getStaticFieldTaint(String fieldSignature, Taint defaultValue) {
        if (!isFieldType(fieldSignature)) {
            return defaultValue;
        }

        return staticFieldsTaint.getOrDefault(fieldSignature, defaultValue);
    }

    public void putStaticFieldTaint(String fieldSignature, Taint t) {
        if (!isFieldType(fieldSignature)) {
            return;
        }

        staticFieldsTaint.put(fieldSignature, t);
    }


}
