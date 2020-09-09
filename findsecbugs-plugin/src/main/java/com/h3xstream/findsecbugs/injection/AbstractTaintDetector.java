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

import com.h3xstream.findsecbugs.taintanalysis.TaintAnalysis;
import com.h3xstream.findsecbugs.taintanalysis.TaintConfig;
import com.h3xstream.findsecbugs.taintanalysis.TaintDataflow;
import com.h3xstream.findsecbugs.taintanalysis.TaintFrame;
import edu.umd.cs.findbugs.BugReporter;
import edu.umd.cs.findbugs.Detector;
import edu.umd.cs.findbugs.asm.FBClassReader;
import edu.umd.cs.findbugs.ba.AnalysisContext;
import edu.umd.cs.findbugs.ba.CFGBuilderException;
import edu.umd.cs.findbugs.ba.ClassContext;
import edu.umd.cs.findbugs.ba.DataflowAnalysisException;
import edu.umd.cs.findbugs.ba.Location;
import edu.umd.cs.findbugs.bcel.BCELUtil;
import edu.umd.cs.findbugs.classfile.CheckedAnalysisException;
import edu.umd.cs.findbugs.classfile.ClassDescriptor;
import edu.umd.cs.findbugs.classfile.FieldOrMethodDescriptor;
import edu.umd.cs.findbugs.classfile.Global;
import edu.umd.cs.findbugs.classfile.MethodDescriptor;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;

import edu.umd.cs.findbugs.classfile.analysis.MethodInfo;
import edu.umd.cs.findbugs.classfile.engine.asm.FindBugsASM;
import edu.umd.cs.findbugs.util.MultiMap;
import edu.umd.cs.findbugs.util.TopologicalSort;
import org.apache.bcel.classfile.Method;
import org.apache.bcel.generic.ConstantPoolGen;
import org.apache.bcel.generic.Instruction;
import org.apache.bcel.generic.InstructionHandle;
import org.apache.bcel.generic.InvokeInstruction;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * Detector designed for extension to allow usage of taint analysis
 *
 * @author David Formanek (Y Soft Corporation, a.s.)
 */
public abstract class AbstractTaintDetector implements Detector {
    
    protected final BugReporter bugReporter;
    
    protected AbstractTaintDetector(BugReporter bugReporter) {
        this.bugReporter = bugReporter;
    }

    /**
     * Allow any concrete implementation of taint detector to skip the analysis of certain files.
     * The purpose can be for optimisation or to trigger bug in specific context.
     *
     * The default implementation returns true to all classes visited.
     *
     * @param classContext Information about the class that is about to be analyzed
     * @return If the given class should be analyze.
     */
    public boolean shouldAnalyzeClass(ClassContext classContext) {
        return true;
    }
    
    @Override
    public void visitClassContext(ClassContext classContext) {
        if(!shouldAnalyzeClass(classContext)) {
            return;
        }

        List<Method> methodsInCallOrder = computeMethodsInCallOrder(classContext);

        for (Method method : methodsInCallOrder) {
            if (classContext.getMethodGen(method) == null) {
                continue;
            }
            try {
                analyzeMethod(classContext, method);
            } catch (CheckedAnalysisException e) {
                logException(classContext, method, e);
            } catch (RuntimeException e) {
                logException(classContext, method, e);
            }
        }

//        for (Method method : classContext.getMethodsInCallOrder()) {
//            if (classContext.getMethodGen(method) == null) {
//                continue;
//            }
//            try {
//                analyzeMethod(classContext, method);
//            } catch (CheckedAnalysisException e) {
//                logException(classContext, method, e);
//            } catch (RuntimeException e) {
//                logException(classContext, method, e);
//            }
//        }
    }

    @Override
    public void report() {
    }
    
    protected void analyzeMethod(ClassContext classContext, Method method)
            throws CheckedAnalysisException {
        TaintDataflow dataflow = getTaintDataFlow(classContext, method);
        ConstantPoolGen cpg = classContext.getConstantPoolGen();
        ClassMethodSignature classMethodSignature = new ClassMethodSignature(
                com.h3xstream.findsecbugs.BCELUtil.getSlashedClassName(classContext.getJavaClass()), method.getName(), method.getSignature());
        for (Iterator<Location> i = getLocationIterator(classContext, method); i.hasNext();) {
            Location location = i.next();
            InstructionHandle handle = location.getHandle();
            Instruction instruction = handle.getInstruction();
            if (!(instruction instanceof InvokeInstruction)) {
                continue;
            }
            InvokeInstruction invoke = (InvokeInstruction) instruction;
            TaintFrame fact = dataflow.getFactAtLocation(location);
            assert fact != null;
            if (!fact.isValid()) {
                continue;
            }

            analyzeLocation(classContext, method, handle, cpg, invoke, fact, classMethodSignature, dataflow.getAnalysis().getTaintConfig());
        }
    }
    
    private static Iterator<Location> getLocationIterator(ClassContext classContext, Method method)
            throws CheckedAnalysisException {
        try {
            return classContext.getCFG(method).locationIterator();
        } catch (CFGBuilderException ex) {
            throw new CheckedAnalysisException("cannot get control flow graph", ex);
        }
    }
    
    private static TaintDataflow getTaintDataFlow(ClassContext classContext, Method method)
            throws CheckedAnalysisException {
        MethodDescriptor descriptor = BCELUtil.getMethodDescriptor(classContext.getJavaClass(), method);
        return Global.getAnalysisCache().getMethodAnalysis(TaintDataflow.class, descriptor);
    }
    
    private void logException(ClassContext classContext, Method method, Exception ex) {
        bugReporter.logError("Exception while analyzing "
                + classContext.getFullyQualifiedMethodName(method) +": " + ex.getMessage(), ex);
    }
    
    abstract protected void analyzeLocation(ClassContext classContext, Method method, InstructionHandle handle,
                                            ConstantPoolGen cpg, InvokeInstruction invoke, TaintFrame fact,
                                            ClassMethodSignature classMethodSignature, TaintConfig taintConfig)
            throws DataflowAnalysisException;


    private static final WeakHashMap<ClassDescriptor, List<Method>> methodsCallOrder = new WeakHashMap<>();

    private static List<Method> computeMethodsInCallOrder(ClassContext classContext) {
        ClassDescriptor classDescriptor = classContext.getClassDescriptor();
        List<Method> result = methodsCallOrder.get(classDescriptor);
        if (result != null) {
            return result;
        }

        List<MethodInfo> xMethods = (List<MethodInfo>) classContext.getXClass().getXMethods();

        final Map<String, MethodInfo> map = new HashMap<>();
        List<MethodInfo> staticMethods = new ArrayList<>();
        for (MethodInfo m : xMethods) {
            map.put(m.getName() + m.getSignature() + m.isStatic(), m);

            if (m.isStatic()) {
                staticMethods.add(m);
            }
        }

        final MultiMap<MethodInfo, MethodInfo> multiMap = getSelfCalls(classDescriptor, map);


        int lastSize = 0;
        List<MethodInfo> reachableNodesFromStaticMethods = new ArrayList<>(staticMethods);
        List<MethodInfo> temp = new ArrayList<>(staticMethods);
        while (lastSize != reachableNodesFromStaticMethods.size()) {
            for (int i = lastSize; i < reachableNodesFromStaticMethods.size(); i++) {
                temp.addAll(multiMap.get(reachableNodesFromStaticMethods.get(i)));
            }
            lastSize = reachableNodesFromStaticMethods.size();

            for (MethodInfo methodInfo : temp) {
                if (!reachableNodesFromStaticMethods.contains(methodInfo)) {
                    reachableNodesFromStaticMethods.add(methodInfo);
                }
            }

            temp.clear();
        }

        TopologicalSort.OutEdges2<MethodInfo> edges1 = new TopologicalSort.OutEdges2<MethodInfo>() {
            @Override
            public Collection<MethodInfo> getOutEdges(MethodInfo method) {
                return multiMap.get(method);
            }

            @Override
            public int score(MethodInfo e) {
                return e.getMethodCallCount();
            }
        };


        List<MethodInfo> sortedMethods = TopologicalSort.sortByCallGraph(reachableNodesFromStaticMethods, edges1);

        for (MethodInfo methodInfo : TopologicalSort.sortByCallGraph(xMethods, edges1)) {
            if (!sortedMethods.contains(methodInfo)) {
                sortedMethods.add(methodInfo);
            }
        }

        assert xMethods.size() == sortedMethods.size();

        result = new ArrayList<>();
        for (MethodInfo sortedMethod : sortedMethods) {
            for (Method javaMethod : classContext.getJavaClass().getMethods()) {
                int hash = FieldOrMethodDescriptor.getNameSigHashCode(javaMethod.getName(), javaMethod.getSignature());

                if (sortedMethod.getNameSigHashCode() == hash
                        && sortedMethod.getName().equals(javaMethod.getName())
                        && sortedMethod.getSignature().equals(javaMethod.getSignature())
                        && sortedMethod.isStatic() == javaMethod.isStatic()) {

                    result.add(javaMethod);

                    break;
                }
            }
        }

        methodsCallOrder.put(classDescriptor, result);

        return result;
    }

    // From edu.umd.cs.findbugs.classfile.engine.SelfMethodCalls, but including ()V methods like <init> and <cinit>
    private static <T> MultiMap<T, T> getSelfCalls(final ClassDescriptor classDescriptor, final Map<String, T> methods) {
        final MultiMap<T, T> map = new MultiMap<>(HashSet.class);

        FBClassReader reader;
        try {
            reader = Global.getAnalysisCache().getClassAnalysis(FBClassReader.class, classDescriptor);
        } catch (CheckedAnalysisException e) {
            AnalysisContext.logError("Error finding self method calls for " + classDescriptor, e);
            return map;
        }
        reader.accept(new ClassVisitor(FindBugsASM.ASM_VERSION) {
            @Override
            public MethodVisitor visitMethod(final int access, final String name, final String desc, String signature,
                                             String[] exceptions) {
                return new MethodVisitor(FindBugsASM.ASM_VERSION) {
                    @Override
                    public void visitMethodInsn(int opcode, String owner, String toName, String toDesc, boolean isInterface) {
                        if (owner.equals(classDescriptor.getClassName())) {
                            T from = methods.get(name + desc + ((access & Opcodes.ACC_STATIC) != 0));
                            T to = methods.get(toName + toDesc + (opcode == Opcodes.INVOKESTATIC));
                            map.add(from, to);
                        }
                    }
                };
            }
        }, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        return map;
    }

}
