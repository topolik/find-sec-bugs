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
import com.h3xstream.findsecbugs.taintanalysis.Taint;
import com.h3xstream.findsecbugs.taintanalysis.TaintConfig;
import com.h3xstream.findsecbugs.taintanalysis.TaintFrame;
import com.h3xstream.findsecbugs.taintanalysis.TaintMethodConfig;
import com.h3xstream.findsecbugs.taintanalysis.data.TaintLocation;
import com.h3xstream.findsecbugs.taintanalysis.taint.TaintFactory;
import edu.umd.cs.findbugs.BugReporter;
import edu.umd.cs.findbugs.Priorities;
import edu.umd.cs.findbugs.SourceLineAnnotation;
import edu.umd.cs.findbugs.ba.AnalysisContext;
import edu.umd.cs.findbugs.ba.ClassContext;
import edu.umd.cs.findbugs.ba.DataflowAnalysisException;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.bcel.Repository;
import org.apache.bcel.classfile.JavaClass;
import org.apache.bcel.classfile.Method;
import org.apache.bcel.generic.ConstantPoolGen;
import org.apache.bcel.generic.InstructionHandle;
import org.apache.bcel.generic.InvokeInstruction;

/**
 * Detector designed for extension to detect injection vulnerabilities
 *
 * @author David Formanek (Y Soft Corporation, a.s.)
 */
public abstract class AbstractInjectionDetector extends AbstractTaintDetector {
    
    protected final Map<ClassMethodSignature, Set<InjectionSink>> injectionSinks = new HashMap<>();
    private final Map<MethodAndSink, Taint> sinkTaints = new HashMap<MethodAndSink, Taint>();
    
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
    }
    
    @Override
    protected void analyzeLocation(ClassContext classContext, Method method, InstructionHandle handle,
                                   ConstantPoolGen cpg, InvokeInstruction invoke, TaintFrame fact,
                                   ClassMethodSignature classMethodSignature, TaintConfig taintConfig)
            throws DataflowAnalysisException {
        SourceLineAnnotation sourceLine = SourceLineAnnotation.fromVisitedInstruction(classContext, method, handle);
        checkSink(cpg, invoke, fact, sourceLine, classMethodSignature, taintConfig);
        InjectionPoint injectionPoint = getInjectionPoint(invoke, cpg, handle);
        for (int offset : injectionPoint.getInjectableArguments()) {
            Taint parameterTaint = fact.getStackValue(offset);

            int priority = getPriorityFromTaintFrame(fact, offset);
            if (priority == Priorities.IGNORE_PRIORITY) {
                continue;
            }

            String injectableMethod = invoke.getClassName(cpg).replaceAll("\\.","/")+"."+invoke.getMethodName(cpg)+invoke.getSignature(cpg);
            InjectionSink injectionSink = new InjectionSink(this, injectionPoint.getBugType(), priority,
                    classContext, method, handle, injectableMethod, offset);
            injectionSink.addLines(parameterTaint.getAllLocations());
            injectionSink.addSources(parameterTaint.getSources());
            if (parameterTaint.isUnresolved()) {
                // add sink to multi map
                Set<InjectionSink> sinkSet = injectionSinks.get(classMethodSignature);
                if (sinkSet == null) {
                    sinkSet = new HashSet<InjectionSink>();
                }
                assert !sinkSet.contains(injectionSink) : "duplicate sink";
                sinkSet.add(injectionSink);
                injectionSinks.put(classMethodSignature, sinkSet);
                sinkTaints.put(new MethodAndSink(classMethodSignature, injectionSink), parameterTaint);
            } else {
                // sink cannot be influenced by other methods calls, so report it immediately
                bugReporter.reportBug(injectionSink.generateBugInstance(true));
            }
            return;
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
        } else if (taint.isUnresolved()){
            return Priorities.LOW_PRIORITY;
        } else {
            return Priorities.IGNORE_PRIORITY;
        }
    }
    
    private void checkSink(ConstantPoolGen cpg, InvokeInstruction invoke, TaintFrame fact,
                           SourceLineAnnotation line, ClassMethodSignature classMethodSignature, TaintConfig taintConfig)
            throws DataflowAnalysisException {

        // Get state from the method config (transfer fields and static fields)
        TaintMethodConfig methodConfig = getMethodConfig(classMethodSignature, taintConfig);
        if (methodConfig == null) {
            methodConfig = TaintMethodConfig.SAFE_CONFIG;
        }

        for (MethodAndSink methodAndSink : getSinks(cpg, invoke, fact)) {
            InjectionSink sink = methodAndSink.getSink();
            Taint sinkTaint = sinkTaints.get(methodAndSink);
            assert sinkTaint != null : "sink taint not stored in advance";

            Taint finalTaint = mergeTaintWithStack(sinkTaint, false, fact, methodConfig, taintConfig);

            // propagate, the taint is still not fully resolved
            if (finalTaint.isUnresolved()) {
                Set<InjectionSink> sinkSet = injectionSinks.get(classMethodSignature);
                if (sinkSet == null) {
                    sinkSet = new HashSet<InjectionSink>();
                }
                sinkSet.add(sink);
                injectionSinks.put(classMethodSignature, sinkSet);
                sinkTaints.put(new MethodAndSink(classMethodSignature, sink), finalTaint);
            } else {
                // confirm sink to be tainted or called only with safe values
                sink.updateSinkPriority(getPriority(finalTaint));
            }

            if (!finalTaint.isSafe()) {
                sink.addLine(line);
                sink.addLines(finalTaint.getAllLocations());
            }
        }
    }

    private Set<MethodAndSink> getSinks(ConstantPoolGen cpg, InvokeInstruction invoke, TaintFrame frame) {
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

    private TaintMethodConfig getMethodConfig(ClassMethodSignature classMethodSignature, TaintConfig taintConfig) {
        String methodId = "." + classMethodSignature.getMethodName() + classMethodSignature.getSignature();
        return taintConfig.get(classMethodSignature.getClassName().concat(methodId));
//        if (config == null) {
//            config = taintConfig.getSuperMethodConfig(classMethodSignature.getClassName(), methodId);
//        }
//        return config;
    }

    private Taint mergeTaintWithStack(Taint taint, boolean mergeChildren, TaintFrame fact, TaintMethodConfig taintMethodConfig, TaintConfig taintConfig) {
        assert taint != null;
        Taint result = taint;

        boolean mergedWithStack = false;
        if (taint.isUnresolved()) {
            result = null;

            // taint consisting of merged parameters only
            if (taint.hasParameters()) {
                Taint transferParametersTaint = mergeTransferParameters(taint.getParameters(), fact);
                assert transferParametersTaint != null;

                result = transferParametersTaint;
            }

            // taint depends on fields
            if (taint.hasFields()) {
                Taint transferFieldsTaint = mergeTransferFields(taint.getFields(), fact, taintMethodConfig, taintConfig);
                assert transferFieldsTaint != null;

                result = transferFieldsTaint.merge(result);
            }

            // taint depends on static fields
            if (taint.hasStaticFields()) {
                Taint transferStaticFieldsTaint = mergeStaticTransferFields(taint.getStaticFields(), taintMethodConfig, taintConfig);
                assert transferStaticFieldsTaint != null;

                result = transferStaticFieldsTaint.merge(result);
            }

            assert result != null;

            if (taint.getNonParametricState() != Taint.State.INVALID) {
                // if the method body has own inner state then merge with parameters
                result = result.merge(Taint.valueOf(taint.getNonParametricState()));
            }

            result.addAllSources(taint.getSources());

            // add original taint locations
            for (TaintLocation unknownLocation : taint.getUnknownLocations()) {
                result.addLocation(unknownLocation, false);
            }
            for (TaintLocation taintLocation : taint.getTaintedLocations()) {
                result.addLocation(taintLocation, true);
            }

            // don't add tags to safe values
            if (!result.isSafe() && taint.hasTags()) {
                for (Taint.Tag tag : taint.getTags()) {
                    result.addTag(tag);
                }
            }
            if (taint.isRemovingTags()) {
                for (Taint.Tag tag : taint.getTagsToRemove()) {
                    result.removeTag(tag);
                }
            }

            // now the "result" contains / references values from the stack (variables, parameters, etc)
            mergedWithStack = true;
        }

        // merge taint class fields with stack
        if (mergeChildren && taint.getFieldTaints() != null) {
            for (Map.Entry<String, Taint> fieldTaintEntry : taint.getFieldTaints().entrySet()) {
                String fieldName = fieldTaintEntry.getKey();
                Taint fieldTaint = fieldTaintEntry.getValue();

                // apply stack to the field taint
                Taint mergedTaint = mergeTaintWithStack(fieldTaint, true, fact, taintMethodConfig, taintConfig);

                mergedTaint.addAllSources(fieldTaint.getSources());

                // merge removes tags so we made a taint copy before
                for (TaintLocation unknownLocation : fieldTaint.getUnknownLocations()) {
                    mergedTaint.addLocation(unknownLocation, false);
                }
                for (TaintLocation taintLocation : fieldTaint.getTaintedLocations()) {
                    mergedTaint.addLocation(taintLocation, true);
                }

                // don't add tags to safe values
                if (!mergedTaint.isSafe() && fieldTaint.hasTags()) {
                    for (Taint.Tag tag : fieldTaint.getTags()) {
                        mergedTaint.addTag(tag);
                    }
                }
                if (fieldTaint.isRemovingTags()) {
                    for (Taint.Tag tag : fieldTaint.getTagsToRemove()) {
                        mergedTaint.removeTag(tag);
                    }
                }

                if (mergedWithStack) {
                    Taint resultFieldTaint = result.getFieldTaint(fieldName);
                    if (resultFieldTaint != null) {
                        // merge field taint with existing field taint
                        mergedTaint = mergedTaint.merge(resultFieldTaint);
                    }
                }

                result.setFieldTaint(fieldName, mergedTaint);
            }

        }

        return result;
    }

    private Taint mergeTransferParameters(Collection<Integer> transferParameters, TaintFrame fact) {
        assert transferParameters != null && !transferParameters.isEmpty();
        Taint taint = null;
        Taint safeTaint = null;
        for (Integer transferParameter : transferParameters) {
            try {
                Taint value = fact.getStackValue(transferParameter);
                if (value.isSafe()) {
                    safeTaint = value.merge(safeTaint);
                } else {
                    taint = value.merge(taint);
                }
            } catch (DataflowAnalysisException ex) {
                throw new RuntimeException("Bad transfer parameter specification", ex);
            }
        }
        assert taint != null || safeTaint != null;
        if (taint == null) {
            return safeTaint;
        }
        return taint;
    }


    private Taint mergeTransferFields(Collection<Taint.FieldTuple> transferFields, TaintFrame fact, TaintMethodConfig taintMethodConfig, TaintConfig taintConfig) {
        assert transferFields != null && !transferFields.isEmpty();
        Taint taint = null;
        Taint safeTaint = null;
        for (Taint.FieldTuple transferField : transferFields) {
            Taint parentTaint = transferField.getParentTaint();

            parentTaint = mergeTaintWithStack(parentTaint, false, fact, taintMethodConfig, taintConfig);

            Taint fieldTaint = parentTaint.getFieldTaint(transferField.getFieldName());
            if (fieldTaint == null) {
                taint = TaintFactory.createTaint(Taint.State.UNKNOWN).merge(taint);
                taint.setField(parentTaint, transferField.getFieldName());
            }
            else if (fieldTaint.isSafe()) {
                safeTaint = fieldTaint.merge(safeTaint);
            } else {
                taint = fieldTaint.merge(taint);
            }
        }

        assert taint != null || safeTaint != null;
        if (taint == null) {
            return safeTaint;
        }
        return taint;
    }

    private Taint mergeStaticTransferFields(Collection<ClassFieldSignature> transferStaticFields, TaintMethodConfig analyzedMethodConfig, TaintConfig taintConfig) {
        assert transferStaticFields != null && !transferStaticFields.isEmpty();
        Taint taint = null;
        Taint safeTaint = null;
        for (ClassFieldSignature transferStaticFieldSig : transferStaticFields) {
            Taint staticFieldTaint = getStaticFieldTaint(transferStaticFieldSig, analyzedMethodConfig, taintConfig);

            if (staticFieldTaint.isSafe()) {
                safeTaint = staticFieldTaint.merge(safeTaint);
            } else {
                taint = staticFieldTaint.merge(taint);
            }
        }

        assert taint != null || safeTaint != null;
        if (taint == null) {
            return safeTaint;
        }
        return taint;
    }


    private Taint getStaticFieldTaint(ClassFieldSignature classFieldSignature, TaintMethodConfig analyzedMethodConfig, TaintConfig taintConfig) {
        Taint staticFieldTaint = analyzedMethodConfig.getStaticFieldTaint(classFieldSignature);

        if (staticFieldTaint != null) {
            return staticFieldTaint;
        }

        staticFieldTaint = taintConfig.getStaticFieldTaint(classFieldSignature);

        if (staticFieldTaint != null) {
            // set reference to the static field like it would be unset
            // static field taint depends on a global static context that can change over time
            staticFieldTaint.addStaticField(classFieldSignature);

            return staticFieldTaint;
        }

        Taint.State state = taintConfig.getFieldTaintState(classFieldSignature.getSignature(), Taint.State.INVALID);
        if (state == Taint.State.INVALID) {
            state = taintConfig.getClassTaintState(classFieldSignature.getClassName(), Taint.State.INVALID);
        }
        if (state == Taint.State.INVALID) {
            state = Taint.State.UNKNOWN;
        }

        staticFieldTaint = TaintFactory.createTaint(state);
        staticFieldTaint.addStaticField(classFieldSignature);

        return staticFieldTaint;
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
