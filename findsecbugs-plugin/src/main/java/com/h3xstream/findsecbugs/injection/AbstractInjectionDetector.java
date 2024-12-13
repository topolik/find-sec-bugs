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
package com.h3xstream.findsecbugs.injection;

import com.h3xstream.findsecbugs.BCELUtil;
import com.h3xstream.findsecbugs.FindSecBugsGlobalConfig;
import com.h3xstream.findsecbugs.taintanalysis.Taint;
import com.h3xstream.findsecbugs.taintanalysis.TaintFrame;
import com.h3xstream.findsecbugs.taintanalysis.data.UnknownSource;
import edu.umd.cs.findbugs.BugReporter;
import edu.umd.cs.findbugs.Priorities;
import edu.umd.cs.findbugs.SourceLineAnnotation;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import edu.umd.cs.findbugs.ba.AnalysisContext;
import edu.umd.cs.findbugs.ba.ClassContext;
import edu.umd.cs.findbugs.ba.DataflowAnalysisException;
import org.apache.bcel.Repository;
import org.apache.bcel.classfile.JavaClass;
import org.apache.bcel.classfile.Method;
import org.apache.bcel.generic.ConstantPoolGen;
import org.apache.bcel.generic.InstructionHandle;
import org.apache.bcel.generic.InvokeInstruction;

import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.logging.Logger;

/**
 * Detector designed for extension to detect injection vulnerabilities
 *
 * @author David Formanek (Y Soft Corporation, a.s.)
 */
public abstract class AbstractInjectionDetector extends AbstractTaintDetector {

    private static final Logger LOGGER = Logger.getLogger(AbstractInjectionDetector.class.getName());
    @SuppressFBWarnings(value="MS_SHOULD_BE_REFACTORED_TO_BE_FINAL", justification="Can't be final because FileOutputStream needs a try-catch.")
    protected static Writer writer = null;
    protected final Map<ClassMethodSignature, Set<InjectionSink>> injectionSinks = new HashMap<>();
    private final Map<MethodAndSink, Taint> sinkTaints = new HashMap<MethodAndSink, Taint>();

    static {
        if (FindSecBugsGlobalConfig.getInstance().isDebugOutputTaintConfigs()) {
            try {
                final String fileName = "derived-sinks.txt";
                writer = new BufferedWriter(new OutputStreamWriter(
                    new FileOutputStream(fileName), "utf-8"));
                // note: writer is not closed until the end
                LOGGER.info("Derived injection sinks configs will be output to " + fileName);
            } catch (UnsupportedEncodingException ex) {
                assert false : ex.getMessage();
            } catch (FileNotFoundException ex) {
                AnalysisContext.logError("File for derived configs cannot be created or opened", ex);
            }
        }
    }

    protected AbstractInjectionDetector(BugReporter bugReporter) {
        super(bugReporter);
    }

    /**
     * Once the analysis is completed, all the collected sinks are reported as bugs.
     */
    @Override
    public void report() {
        // collect sinks and report each once
        Set<InjectionSink> injectionSinksToReport = new HashSet<InjectionSink>();
        for (Set<InjectionSink> injectionSinkSet : injectionSinks.values()) {
            for (InjectionSink injectionSink : injectionSinkSet) {
                injectionSinksToReport.add(injectionSink);
            }
        }
        for (InjectionSink injectionSink : injectionSinksToReport) {
            bugReporter.reportBug(injectionSink.generateBugInstance(false));
        }

        if (FindSecBugsGlobalConfig.getInstance().isDebugOutputSinkConfigs()) {
            for (Map.Entry<MethodAndSink, Taint> methodAndSinkTaintEntry : sinkTaints.entrySet()) {
                MethodAndSink methodAndSink = methodAndSinkTaintEntry.getKey();
                ClassMethodSignature classMethodSignature = methodAndSink.getClassMethodSignature();
                InjectionSink sink = methodAndSink.getSink();
                Taint taint = methodAndSinkTaintEntry.getValue();

                for (UnknownSource source : taint.getSources()) {
                    switch (source.getState()) {
                        case NULL:
                            continue;
                        case SAFE:
                            continue;
                    }

                    try {
                        switch (source.getSourceType()) {
                            case FIELD:
                                // we ignore fields as injection sinks for taint propagation, for now
                                break;
                            case PARAMETER:
                                writer.append(classMethodSignature.getClassName());
                                writer.append('.');
                                writer.append(classMethodSignature.getMethodName());
                                writer.append(classMethodSignature.getSignature());
                                writer.append(':');
                                writer.append(String.valueOf(source.getParameterIndex()));
                                writer.append('|');
                                writer.append(sink.getBugType());
                                writer.append('\n');
                                writer.flush();
                                break;
                            case RETURN:
                                // we ignore method return sources, they cannot be added as an injection sink
                                break;
                            default:
                                AnalysisContext.logError("Unknown source type: " + source.getSourceType() + " for " + source);
                        }
                    } catch (IOException ex) {
                        AnalysisContext.logError("Unable to write derived injection sinks: " + ex.getMessage(), ex);
                    }
                }
            }
        }
    }

    @Override
    protected void analyzeLocation(ClassContext classContext, Method method, InstructionHandle handle,
            ConstantPoolGen cpg, InvokeInstruction invoke, TaintFrame fact, ClassMethodSignature classMethodSignature)
            throws DataflowAnalysisException {
        SourceLineAnnotation sourceLine = SourceLineAnnotation.fromVisitedInstruction(classContext, method, handle);

        // (2) Taint propagation: Check sinks that we derived earlier and propagate taint if we call them here
        checkDerivedSinks(cpg, invoke, fact, sourceLine, classMethodSignature);

        // (1) Create a new sink from a defined injection point and register into list of sinks for the method
        InjectionPoint injectionPoint = getInjectionPoint(invoke, cpg, handle);
        for (int offset : injectionPoint.getInjectableArguments()) {
            int priority = getPriorityFromTaintFrame(fact, offset);
            if (priority == Priorities.IGNORE_PRIORITY) {
                continue;
            }
            // Get the actual taint from the stack that flows into the injection point / sink
            Taint parameterTaint = fact.getStackValue(offset);

            // Create new sink object
            String injectableMethod = invoke.getClassName(cpg).replaceAll("\\.","/")+"."+invoke.getMethodName(cpg)+invoke.getSignature(cpg);
            InjectionSink injectionSink = new InjectionSink(this, injectionPoint.getBugType(), priority,
                    classContext, method, handle, injectableMethod, offset);
            injectionSink.addLines(parameterTaint.getAllLocations());
            injectionSink.addSources(parameterTaint.getSources());

            // if the taint flows into the sink from the outside
            // then register the sink for taint propagation - see step (2)
            if (parameterTaint.hasParameters()) {
                registerSinkToClassAndInterfaces(classMethodSignature, injectionSink, parameterTaint);
            } else {
                // sink cannot be influenced by other methods calls, so report it immediately
                bugReporter.reportBug(injectionSink.generateBugInstance(true));
            }
            // Why return after the first injectable argument only and skipping the rest?
            // Because we want to avoid reporting multiple sinks for the same injection point.
            // The report won't be complete/full but we expect developers to fix all issues at once.
            // If devs don't fix all bugs at once then we'll report anyway as soon as they fix the first one and re-run.
            // On the other hand this behaviour is not suitable for deriving all sinks and their configs for complete
            // taint propagation.
            if(!FindSecBugsGlobalConfig.getInstance().isDebugOutputSinkConfigs()) {
                return;
            }
        }
    }

    /**
     * The default implementation of <code>getPriorityFromTaintFrame()</code> can be overridden if the detector must base its
     * priority on multiple parameters or special conditions like constant values.
     *
     * By default, this method will call the <code>getPriority()</code> method with the parameter taint at the specified offset.
     *
     * @param fact The TaintFrame for the inspected instruction call.
     * @param offset The offset of the checked parameter.
     * @return Priorities interface values from 1 to 5 (Enum-like interface)
     * @throws DataflowAnalysisException An exception thrown when the TaintFrame cannot be analyzed.
     */
    protected int getPriorityFromTaintFrame(TaintFrame fact, int offset)
            throws DataflowAnalysisException {
        Taint parameterTaint = fact.getStackValue(offset);
        return getPriority(parameterTaint);
    }

    /**
     * The default implementation of <code>getPriority()</code> can be overridden if the severity and the confidence for risk
     * is particular.
     *
     * By default, injection will be rated "High" if the complete link between source and sink is made.
     * If it is not the case but concatenation with external source is made, "Medium" is used.
     *
     * @param taint Detail about the state of the value passed (Cumulative information leading to the variable passed).
     * @return Priorities interface values from 1 to 5 (Enum-like interface)
     */
    protected int getPriority(Taint taint) {
        if (taint.isTainted()) {
            return Priorities.HIGH_PRIORITY;
        } else if (!taint.isSafe()) {
            return Priorities.NORMAL_PRIORITY;
        } else {
            return Priorities.IGNORE_PRIORITY;
        }
    }

    private void checkDerivedSinks(ConstantPoolGen cpg, InvokeInstruction invoke, TaintFrame fact,
                                   SourceLineAnnotation line, ClassMethodSignature classMethodSignature) throws DataflowAnalysisException {
        for (MethodAndSink methodAndSink : getDerivedSinks(cpg, invoke, fact)) {
            Taint sinkTaint = sinkTaints.get(methodAndSink);
            assert sinkTaint != null : "sink taint not stored in advance";
            Set<Integer> taintParameters = sinkTaint.getParameters();
            Taint finalTaint = Taint.valueOf(sinkTaint.getNonParametricState());
            // If the taint flows into the sink through the parameters of the method we currently call (the usual way of taint propagation)
            // then propagate taint from the current stack into the method arguments
            for (Integer offset : taintParameters) {
                Taint parameterTaint = fact.getStackValue(offset);
                finalTaint = Taint.merge(finalTaint, parameterTaint);
            }
            if (finalTaint == null) {
                continue;
            }
            if (!sinkTaint.isSafe() && sinkTaint.hasTags()) {
                for (Taint.Tag tag : sinkTaint.getTags()) {
                    finalTaint.addTag(tag);
                }
            }
            if (sinkTaint.isRemovingTags()) {
                for (Taint.Tag tag : sinkTaint.getTagsToRemove()) {
                    finalTaint.removeTag(tag);
                }
            }
            InjectionSink sink = methodAndSink.getSink();
            // update the underlying sink with new information - the new taint that we are propagating from the caller
            if (!finalTaint.isSafe()) {
                sink.addLine(line);
                sink.addLines(finalTaint.getAllLocations());
                sink.addSources(finalTaint.getSources());
            }
            // register the underlying sink as a new sink in the current method
            if (finalTaint.hasParameters()) {
                registerSinkToClassAndInterfaces(classMethodSignature, sink, finalTaint);
            } else {
                // confirm sink to be tainted or called only with safe values
                sink.updateSinkPriority(getPriority(finalTaint));
            }
        }
    }

    private Set<MethodAndSink> getDerivedSinks(ConstantPoolGen cpg, InvokeInstruction invoke, TaintFrame frame) {
        ClassMethodSignature classMethodSignature = new ClassMethodSignature(
                getInstanceClassName(cpg, invoke, frame), invoke.getMethodName(cpg), invoke.getSignature(cpg));

        Set<InjectionSink> sinks = injectionSinks.get(classMethodSignature);
        if (sinks != null) {
            assert !sinks.isEmpty() : "empty set of sinks";
            return getMethodAndSinks(classMethodSignature, sinks);
        }
        try {
            if (classMethodSignature.getClassName().endsWith("]")) {
                // not a real class
                return Collections.emptySet();
            }
            JavaClass javaClass = Repository.lookupClass(classMethodSignature.getClassName());
            assert javaClass != null;
            return getSuperSinks(javaClass, classMethodSignature);
        } catch (ClassNotFoundException ex) {
            AnalysisContext.reportMissingClass(ex);
        }
        return Collections.emptySet();
    }

    private Set<MethodAndSink> getMethodAndSinks(ClassMethodSignature classMethodSignature, Set<InjectionSink> sinks) {
        Set<MethodAndSink> methodAndSinks = new HashSet<MethodAndSink>();
        for (InjectionSink sink : sinks) {
            methodAndSinks.add(new MethodAndSink(classMethodSignature, sink));
        }
        return methodAndSinks;
    }

    private Set<MethodAndSink> getSuperSinks(JavaClass javaClass, ClassMethodSignature classMethodSignature) throws ClassNotFoundException {
        Set<String> classNames = BCELUtil.getParentClassNames(javaClass);

        for (String className : classNames) {
            classMethodSignature.setClassName(className);
            Set<InjectionSink> sinks = injectionSinks.get(classMethodSignature);
            if (sinks != null) {
                return getMethodAndSinks(classMethodSignature, sinks);
            }
        }

        return Collections.emptySet();
    }

    /**
     * Associate the found sink and taint to the class and it's interfaces for taint propagation
     */
    private void registerSinkToClassAndInterfaces(ClassMethodSignature classMethodSignature, InjectionSink injectionSink, Taint taint) {

        registerSink(classMethodSignature, injectionSink, taint);

        // https://docs.oracle.com/en/java/javase/17/docs/api/allpackages-index.html
        List<String> systemPackagesPrefixes = Arrays.asList("com.sun.", "java.", "javax.", "jdk.", "netscape", "org.ietf.", "org.w3c.", "org.xml.");

        try {
            // Register also the implemented interfaces to be vulnerable now
            JavaClass javaClass = Repository.lookupClass(classMethodSignature.getClassName());
            assert javaClass != null;
            Queue<JavaClass> queue = new LinkedList<>();
            queue.offer(javaClass);
            while (!queue.isEmpty()) {
                JavaClass clazz = queue.poll();
                try {
                    for (JavaClass superClass : clazz.getSuperClasses()) {
                        String packageName = superClass.getPackageName();
                        boolean isSystemClass = false;
                        for (String systemPackagesPrefix : systemPackagesPrefixes) {
                            if (packageName.startsWith(systemPackagesPrefix)) {
                                isSystemClass = true;
                                break;
                            }
                        }
                        if (!isSystemClass) {
                            queue.offer(superClass);
                        }
                    }
                    for (JavaClass interfaceClass : clazz.getInterfaces()) {
                        String packageName = interfaceClass.getPackageName();
                        boolean isSystemClass = false;
                        for (String systemPackagesPrefix : systemPackagesPrefixes) {
                            if (packageName.startsWith(systemPackagesPrefix)) {
                                isSystemClass = true;
                                break;
                            }
                        }
                        if (!isSystemClass) {
                            queue.offer(interfaceClass);
                        }

                        for (Method iMethod : interfaceClass.getMethods()) {
                            if (!iMethod.getName().equals(classMethodSignature.getMethodName())) {
                                continue;
                            }
                            if (!iMethod.getSignature().equals(classMethodSignature.getSignature())) {
                                continue;
                            }

                            ClassMethodSignature interfaceMethodSignature = new ClassMethodSignature(
                                    BCELUtil.getSlashedClassName(interfaceClass),
                                    classMethodSignature.getMethodName(),
                                    classMethodSignature.getSignature());

                            registerSink(interfaceMethodSignature, injectionSink, taint);
                        }
                    }
                } catch (ClassNotFoundException e) {
                    AnalysisContext.reportMissingClass(e);
                }
            }
        } catch (ClassNotFoundException e) {
            AnalysisContext.reportMissingClass(e);
        }
    }

    /**
     * Associates the found sink & taint with the {@param classMethodSignature}
     */
    private void registerSink(ClassMethodSignature classMethodSignature, InjectionSink injectionSink, Taint taint){
        Set<InjectionSink> sinkSet = injectionSinks.get(classMethodSignature);
        if (sinkSet == null) {
            sinkSet = new HashSet<InjectionSink>();
        }
        sinkSet.add(injectionSink);
        injectionSinks.put(classMethodSignature, sinkSet);
        sinkTaints.put(new MethodAndSink(classMethodSignature, injectionSink), taint);
    }

    private static String getInstanceClassName(ConstantPoolGen cpg, InvokeInstruction invoke, TaintFrame frame) {
        try {
            int instanceIndex = BCELUtil.getNumArgumentsIncludingObjectInstance(invoke, cpg) - 1;
            if (instanceIndex != -1) {
                assert instanceIndex < frame.getStackDepth();
                Taint instanceTaint = frame.getStackValue(instanceIndex);
                String className = instanceTaint.getRealInstanceClassName();
                if (className != null) {
                    return className;
                }
            }
        } catch (DataflowAnalysisException ex) {
            assert false : ex.getMessage();
        }

        return BCELUtil.getSlashedClassName(cpg, invoke);
    }

    abstract protected InjectionPoint getInjectionPoint(
            InvokeInstruction invoke, ConstantPoolGen cpg, InstructionHandle handle);
}