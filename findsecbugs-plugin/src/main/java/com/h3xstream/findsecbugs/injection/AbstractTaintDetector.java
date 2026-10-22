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

import com.h3xstream.findsecbugs.taintanalysis.TaintDataflow;
import com.h3xstream.findsecbugs.taintanalysis.TaintFrame;
import edu.umd.cs.findbugs.BugReporter;
import edu.umd.cs.findbugs.Detector;
import edu.umd.cs.findbugs.ba.CFGBuilderException;
import edu.umd.cs.findbugs.ba.ClassContext;
import edu.umd.cs.findbugs.ba.DataflowAnalysisException;
import edu.umd.cs.findbugs.ba.Location;
import edu.umd.cs.findbugs.bcel.BCELUtil;
import edu.umd.cs.findbugs.classfile.CheckedAnalysisException;
import edu.umd.cs.findbugs.classfile.Global;
import edu.umd.cs.findbugs.classfile.MethodDescriptor;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import org.apache.bcel.classfile.Attribute;
import org.apache.bcel.classfile.BootstrapMethod;
import org.apache.bcel.classfile.BootstrapMethods;
import org.apache.bcel.classfile.Constant;
import org.apache.bcel.classfile.ConstantCP;
import org.apache.bcel.classfile.ConstantInvokeDynamic;
import org.apache.bcel.classfile.ConstantMethodHandle;
import org.apache.bcel.classfile.ConstantNameAndType;
import org.apache.bcel.classfile.ConstantPool;
import org.apache.bcel.classfile.JavaClass;
import org.apache.bcel.classfile.Method;
import org.apache.bcel.generic.ConstantPoolGen;
import org.apache.bcel.generic.INVOKEDYNAMIC;
import org.apache.bcel.generic.Instruction;
import org.apache.bcel.generic.InstructionHandle;
import org.apache.bcel.generic.InvokeInstruction;
import org.apache.bcel.generic.MethodGen;

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
        Set<Method> analyzed = new HashSet<Method>();
        for (Method method : classContext.getMethodsInCallOrder()) {
            if (method.isStatic()) {
                analyzeMethodAndLambdas(classContext, method, analyzed, false);
            }
        }
        for (Method method : classContext.getMethodsInCallOrder()) {
            if (!method.isStatic()) {
                analyzeMethodAndLambdas(classContext, method, analyzed, false);
            }
        }
    }

    /**
     * Analyzes the lambda bodies first, so their sinks are known at the invokedynamic sites. A lambda
     * body is pulled ahead of the call order, so its same-class callees are analyzed before it too.
     * Other methods keep the call order, the static field taint relies on callers coming first.
     */
    private void analyzeMethodAndLambdas(ClassContext classContext, Method method, Set<Method> analyzed,
                                         boolean lambda) {
        if (!analyzed.add(method)) {
            return;
        }
        MethodGen methodGen = classContext.getMethodGen(method);
        if (methodGen == null) {
            return;
        }
        JavaClass javaClass = classContext.getJavaClass();
        ConstantPoolGen cpg = classContext.getConstantPoolGen();
        for (InstructionHandle handle : methodGen.getInstructionList().getInstructionHandles()) {
            Instruction instruction = handle.getInstruction();
            Method callee = null;
            if (instruction instanceof INVOKEDYNAMIC) {
                callee = getLambdaImplementation(javaClass, cpg, (INVOKEDYNAMIC) instruction);
            } else if (lambda && (instruction instanceof InvokeInstruction)) {
                callee = getSameClassMethod(javaClass, cpg, (InvokeInstruction) instruction);
            }
            if (callee != null) {
                analyzeMethodAndLambdas(classContext, callee, analyzed, true);
            }
        }
        try {
            analyzeMethod(classContext, method);
        } catch (CheckedAnalysisException e) {
            logException(classContext, method, e);
        } catch (RuntimeException e) {
            logException(classContext, method, e);
        }
    }

    private static Method getSameClassMethod(JavaClass javaClass, ConstantPoolGen cpg, InvokeInstruction invoke) {
        if (!javaClass.getClassName().equals(invoke.getReferenceType(cpg).toString())) {
            return null;
        }
        return findMethod(javaClass, invoke.getMethodName(cpg), invoke.getSignature(cpg));
    }

    private static Method findMethod(JavaClass javaClass, String name, String signature) {
        for (Method method : javaClass.getMethods()) {
            if (method.getName().equals(name) && method.getSignature().equals(signature)) {
                return method;
            }
        }
        return null;
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
            if (invoke instanceof INVOKEDYNAMIC) {
                analyzeLambdaLocation(classContext, method, handle, cpg, (INVOKEDYNAMIC) invoke, fact, classMethodSignature);
                continue;
            }
            analyzeLocation(classContext, method, handle, cpg, invoke, fact, classMethodSignature);
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
                + classContext.getFullyQualifiedMethodName(method), ex);
    }
    
    abstract protected void analyzeLocation(ClassContext classContext, Method method, InstructionHandle handle,
            ConstantPoolGen cpg, InvokeInstruction invoke, TaintFrame fact, ClassMethodSignature classMethodSignature)
            throws DataflowAnalysisException;

    /**
     * Called for each invokedynamic instruction, the default implementation does nothing.
     */
    protected void analyzeLambdaLocation(ClassContext classContext, Method method, InstructionHandle handle,
            ConstantPoolGen cpg, INVOKEDYNAMIC invoke, TaintFrame fact, ClassMethodSignature classMethodSignature)
            throws DataflowAnalysisException {
    }

    protected static Method getLambdaImplementation(JavaClass javaClass, ConstantPoolGen cpg, INVOKEDYNAMIC invoke) {
        ConstantPool cp = cpg.getConstantPool();
        BootstrapMethods bootstrapMethods = null;
        for (Attribute attribute : javaClass.getAttributes()) {
            if (attribute instanceof BootstrapMethods) {
                bootstrapMethods = (BootstrapMethods) attribute;
            }
        }
        if (bootstrapMethods == null) {
            return null;
        }
        ConstantInvokeDynamic invokeDynamic = (ConstantInvokeDynamic) cp.getConstant(invoke.getIndex());
        BootstrapMethod bootstrapMethod =
                bootstrapMethods.getBootstrapMethods()[invokeDynamic.getBootstrapMethodAttrIndex()];
        ConstantMethodHandle bootstrapHandle =
                (ConstantMethodHandle) cp.getConstant(bootstrapMethod.getBootstrapMethodRef());
        ConstantCP bootstrapReference = (ConstantCP) cp.getConstant(bootstrapHandle.getReferenceIndex());
        int[] bootstrapArguments = bootstrapMethod.getBootstrapArguments();
        if (!"java.lang.invoke.LambdaMetafactory".equals(bootstrapReference.getClass(cp))
                || bootstrapArguments.length < 2) {
            return null;
        }
        Constant implementation = cp.getConstant(bootstrapArguments[1]);
        if (!(implementation instanceof ConstantMethodHandle)) {
            return null;
        }
        ConstantCP implementationReference =
                (ConstantCP) cp.getConstant(((ConstantMethodHandle) implementation).getReferenceIndex());
        if (!javaClass.getClassName().equals(implementationReference.getClass(cp))) {
            return null;
        }
        ConstantNameAndType nameAndType =
                (ConstantNameAndType) cp.getConstant(implementationReference.getNameAndTypeIndex());
        return findMethod(javaClass, nameAndType.getName(cp), nameAndType.getSignature(cp));
    }
}
