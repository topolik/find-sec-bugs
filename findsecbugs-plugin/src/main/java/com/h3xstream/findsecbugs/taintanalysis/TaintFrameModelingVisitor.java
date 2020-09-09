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
import com.h3xstream.findsecbugs.FindSecBugsGlobalConfig;
import com.h3xstream.findsecbugs.common.ByteCode;
import com.h3xstream.findsecbugs.injection.ClassFieldSignature;
import com.h3xstream.findsecbugs.taintanalysis.data.TaintLocation;
import com.h3xstream.findsecbugs.taintanalysis.data.UnknownSource;
import com.h3xstream.findsecbugs.taintanalysis.data.UnknownSourceType;
import com.h3xstream.findsecbugs.taintanalysis.taint.TaintFactory;
import edu.umd.cs.findbugs.ba.AbstractFrameModelingVisitor;
import edu.umd.cs.findbugs.ba.AnalysisContext;
import edu.umd.cs.findbugs.ba.DataflowAnalysisException;
import edu.umd.cs.findbugs.ba.InvalidBytecodeException;
import edu.umd.cs.findbugs.ba.generic.GenericSignatureParser;
import edu.umd.cs.findbugs.classfile.MethodDescriptor;
import edu.umd.cs.findbugs.util.ClassName;

import java.lang.reflect.Modifier;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import org.apache.bcel.Const;
import org.apache.bcel.Repository;
import org.apache.bcel.classfile.Field;
import org.apache.bcel.classfile.JavaClass;
import org.apache.bcel.generic.*;

/**
 * Visitor to make instruction transfer of taint values easier
 *
 * @author David Formanek (Y Soft Corporation, a.s.)
 */
public class TaintFrameModelingVisitor extends AbstractFrameModelingVisitor<Taint, TaintFrame> {

    private static final Logger LOG = Logger.getLogger(TaintFrameModelingVisitor.class.getName());

    private static final Map<String, Taint.Tag> REPLACE_TAGS;
    private final MethodDescriptor methodDescriptor;
    private final TaintConfig taintConfig;
    private final TaintMethodConfig analyzedMethodConfig;

    private final List<TaintFrameAdditionalVisitor> visitors;
    private final MethodGen methodGen;
    private String regexValue;

    static {
        REPLACE_TAGS = new HashMap<String, Taint.Tag>();
        REPLACE_TAGS.put("\r", Taint.Tag.CR_ENCODED);
        REPLACE_TAGS.put("\n", Taint.Tag.LF_ENCODED);
        REPLACE_TAGS.put("\"", Taint.Tag.QUOTE_ENCODED);
        REPLACE_TAGS.put("'", Taint.Tag.APOSTROPHE_ENCODED);
        REPLACE_TAGS.put("<", Taint.Tag.LT_ENCODED);
    }

    /**
     * Constructs the object and stores the parameters
     *
     * @param cpg constant pool gen for super class
     * @param method descriptor of analysed method
     * @param taintConfig current configured and derived taint summaries
     * @throws NullPointerException if arguments method or taintConfig is null
     */
    public TaintFrameModelingVisitor(ConstantPoolGen cpg, MethodDescriptor method,
            TaintConfig taintConfig, List<TaintFrameAdditionalVisitor> visitors,MethodGen methodGen) {
        super(cpg);
        if (method == null) {
            throw new NullPointerException("null method descriptor");
        }
        if (taintConfig == null) {
            throw new NullPointerException("null taint config");
        }
        this.methodDescriptor = method;
        this.taintConfig = taintConfig;
        this.analyzedMethodConfig = new TaintMethodConfig(false);
        analyzedMethodConfig.setTypeSignature(methodDescriptor.getClassDescriptor().getClassName() + "." + methodDescriptor.getName() + methodDescriptor.getSignature());
        this.visitors = visitors;
        this.methodGen = methodGen;
    }

    private Collection<Integer> getMutableStackIndices(String signature) {
        assert signature != null && !signature.isEmpty();
        ArrayList<Integer> indices = new ArrayList<Integer>();
        int stackIndex = 0;
        GenericSignatureParser parser = new GenericSignatureParser(signature);
        Iterator<String> iterator = parser.parameterSignatureIterator();
        while (iterator.hasNext()) {
            String parameter = iterator.next();
            if ((parameter.startsWith("L") || parameter.startsWith("["))
                    && !taintConfig.isClassImmutable(parameter)) {
                indices.add(stackIndex);
            }
            if (parameter.equals("D") || parameter.equals("J")) {
                // double and long types takes two slots
                stackIndex += 2;
            } else {
                stackIndex++;
            }
        }
        for (int i = 0; i < indices.size(); i++) {
            int reverseIndex = stackIndex - indices.get(i) - 1;
            assert reverseIndex >= 0;
            indices.set(i, reverseIndex);
        }
        return indices;
    }

    @Override
    public void analyzeInstruction(Instruction ins) throws DataflowAnalysisException {
        //Print the bytecode instruction if it is globally configured
        if (FindSecBugsGlobalConfig.getInstance().isDebugPrintInvocationVisited()
                && ins instanceof InvokeInstruction) {
            //System.out.println(getFrame().toString());
            ByteCode.printOpCode(ins, cpg);
        } else if (FindSecBugsGlobalConfig.getInstance().isDebugPrintInstructionVisited()) {
            ByteCode.printOpCode(ins, cpg);
        }
        super.analyzeInstruction(ins);

        if (FindSecBugsGlobalConfig.getInstance().isDebugPrintInstructionVisited()) {
            System.out.println(Arrays.stream(getFrame().toString().split("\n")).collect(Collectors.joining( "\n    ", "\n    ", "\n")));
        }
    }

    @Override
    public Taint getDefaultValue() {
        return new Taint(Taint.State.UNKNOWN);
    }

    @Override
    public void visitLDC(LDC ldc) {
        Taint taint = TaintFactory.createTaint(ldc.getType(cpg).getSignature(), Taint.State.SAFE);
        Object value = ldc.getValue(cpg);
        if (value instanceof String) {
            taint.setConstantValue((String) value);
        }
        if (FindSecBugsGlobalConfig.getInstance().isDebugTaintState()) {
            if (value instanceof String) {
                taint.setDebugInfo("\"" + value + "\"");
            } else {
                taint.setDebugInfo("LDC " + ldc.getType(cpg).getSignature());
            }
        }
        getFrame().pushValue(taint);
    }

    @Override
    public void visitLDC2_W(LDC2_W obj) {
        // double and long type takes two slots in BCEL
        if (FindSecBugsGlobalConfig.getInstance().isDebugTaintState()) {
            pushSafeDebug("partial long/double");
            pushSafeDebug("partial long/double");
        } else {
            pushSafe();
            pushSafe();
        }
    }

    @Override
    public void visitBIPUSH(BIPUSH obj) {
        Taint taint = TaintFactory.createTaint(Taint.State.SAFE);
        // assume each pushed byte is a char
        taint.setConstantValue(String.valueOf((char) obj.getValue().byteValue()));
        getFrame().pushValue(taint);
    }

    @Override
    public void visitSIPUSH(SIPUSH obj) {
        Taint taint = TaintFactory.createTaint(Taint.State.SAFE);
        // assume each pushed short is a char (for non-ASCII characters)
        taint.setConstantValue(String.valueOf((char) obj.getValue().shortValue()));
        getFrame().pushValue(taint);
    }

    @Override
    public void visitGETSTATIC(GETSTATIC obj) {
        ObjectType objectType = obj.getLoadClassType(getCPG());

        // Scala uses some classes to represent null instances of objects
        // If we find one of them, we will handle it as a Java Null
        if (objectType.getSignature().equals("Lscala/collection/immutable/Nil$;")) {

            if (FindSecBugsGlobalConfig.getInstance().isDebugTaintState()) {
                getFrame().pushValue(TaintFactory.createTaint(Taint.State.NULL).setDebugInfo("NULL"));
            } else {
                getFrame().pushValue(TaintFactory.createTaint(Taint.State.NULL));
            }
        } else {
            ClassFieldSignature classFieldSignature = new ClassFieldSignature(BCELUtil.getSlashedClassName(cpg, obj), obj.getName(cpg));

            Taint taint = getStaticFieldTaint(classFieldSignature, analyzedMethodConfig,  taintConfig);

            String fieldTypeSignature = obj.getSignature(cpg);
            if (taint.getState().equals(Taint.State.SAFE) && taintConfig.isClassImmutable(fieldTypeSignature)) {
                // immutable final fields with SAFE taint can be treated as globally safe regardless of static context
                try {
                    JavaClass javaClass = Repository.lookupClass(objectType.getClassName());
                    for (Field field : javaClass.getFields()) {
                        if (!Modifier.isFinal(field.getModifiers())
                                || !field.getName().equals(classFieldSignature.getFieldName())
                                || !field.getSignature().equals(fieldTypeSignature)) {

                            continue;
                        }
                        Taint oldTaint = taint;
                        taint = TaintFactory.createTaint(fieldTypeSignature, Taint.State.SAFE);
                        taint.setConstantValue(oldTaint.getConstantValue());
                    }

                } catch (ClassNotFoundException ex) {
                    AnalysisContext.reportMissingClass(ex);
                }
            }

            if (!taint.getState().equals(Taint.State.SAFE)){
                taint.addLocation(getTaintLocation(), false);
            }
            taint.addSource(new UnknownSource(UnknownSourceType.FIELD,taint.getState()).setSignatureField(classFieldSignature.getSignature()));

            int numConsumed = getNumWordsConsumed(obj);
            int numProduced = getNumWordsProduced(obj);
            modelInstruction(obj, numConsumed, numProduced, taint);

            notifyAdditionalVisitorField(obj, methodGen, getFrame(), taint, numProduced);
        }
    }

    @Override
    public void visitACONST_NULL(ACONST_NULL obj) {
        if (FindSecBugsGlobalConfig.getInstance().isDebugTaintState()) {
            getFrame().pushValue(TaintFactory.createTaint(Taint.State.NULL).setDebugInfo("NULL"));
        } else {
            getFrame().pushValue(TaintFactory.createTaint(Taint.State.NULL));
        }
    }

    @Override
     public void visitICONST(ICONST obj) {
        Taint t = TaintFactory.createTaint(Taint.State.SAFE);
        if (FindSecBugsGlobalConfig.getInstance().isDebugTaintState()) {
            t.setDebugInfo("" + obj.getValue().intValue());
        }
        getFrame().pushValue(t);
    }

    @Override
    public void visitGETFIELD(GETFIELD obj) {
        String fieldName = obj.getName(cpg);
        String fieldSig = BCELUtil.getSlashedClassName(cpg, obj)+"."+ fieldName;
        Taint.State state = taintConfig.getFieldTaintState(fieldSig, Taint.State.INVALID);
        if (state == Taint.State.INVALID) {
            state = taintConfig.getClassTaintState(obj.getSignature(cpg), Taint.State.INVALID);
        }
        if (state == Taint.State.INVALID) {
            state = Taint.State.UNKNOWN;
        }

        Taint taint = null;
        // TODO: reorder for performance reasons (get a hashmap value here first vs. traversing classes above)
        try {
            Taint parentTaint = getFrame().getTopValue();

            taint = parentTaint.getFieldTaint(fieldName);
            if (taint == null) {
                taint = TaintFactory.createTaint(obj.getSignature(cpg), state);
                // taint depends on a field
                taint.setField(parentTaint, fieldName);
            } else {
                state = taint.getState();
            }

        } catch (DataflowAnalysisException e) {
        }

        if (!state.equals(Taint.State.SAFE)){
            taint.addLocation(getTaintLocation(), false);
        }
        taint.addSource(new UnknownSource(UnknownSourceType.FIELD,state).setSignatureField(fieldSig));
        if (FindSecBugsGlobalConfig.getInstance().isDebugTaintState()) {
            taint.setDebugInfo("." + obj.getFieldName(cpg));
        }
        int numConsumed = getNumWordsConsumed(obj);
        int numProduced = getNumWordsProduced(obj);
        modelInstruction(obj, numConsumed, numProduced, taint);


        notifyAdditionalVisitorField(obj, methodGen, getFrame(), taint, numProduced);
    }

    @Override
    public void visitPUTFIELD(PUTFIELD obj) {
        try {
            Taint[] operands = new Taint[2];
            getFrame().getTopStackWords(operands);

            Taint parentTaint = operands[0];
            Taint fieldTaint = operands[1];

            String fieldName = obj.getFieldName(cpg);
            parentTaint.setFieldTaint(fieldName, fieldTaint);

            if (parentTaint.hasValidVariableIndex()) {
                int variableIndex = parentTaint.getVariableIndex();
                getFrame().getValue(variableIndex).setFieldTaint(fieldName, fieldTaint);
            }

            if (!fieldTaint.getState().equals(Taint.State.SAFE)){
                fieldTaint.addLocation(getTaintLocation(), false);
            }

            String fieldSig = BCELUtil.getSlashedClassName(cpg, obj) + "." + fieldName;
            fieldTaint.addSource(new UnknownSource(UnknownSourceType.FIELD, fieldTaint.getState()).setSignatureField(fieldSig));
            if (FindSecBugsGlobalConfig.getInstance().isDebugTaintState()) {
                fieldTaint.setDebugInfo(fieldSig);
            }

        } catch (DataflowAnalysisException e) {
        }

        visitPutFieldOp(obj);
    }

    @Override
    public void visitPUTSTATIC(PUTSTATIC obj) {
        try {
            ClassFieldSignature classFieldSignature = new ClassFieldSignature(BCELUtil.getSlashedClassName(cpg, obj), obj.getName(cpg));
//            Taint staticTaint = analyzedMethodConfig.getStaticFieldTaint(fieldSig, taintConfig);
            Taint t = getFrame().getTopValue();
//            t = t.merge(staticTaint);

            Taint.State state = t.getState();

            if (!state.equals(Taint.State.SAFE)){
                t.addLocation(getTaintLocation(), false);
            }
            t.addSource(new UnknownSource(UnknownSourceType.FIELD,state).setSignatureField(classFieldSignature.getSignature()));

            // we are escaping a method context into a global class context
            // method parameters and variables make no sense there
            // 1. clear any method parameters
            t.clearParameters();
            // 2. clear method variable indexes
            t.invalidateVariableIndex();

            if (Const.STATIC_INITIALIZER_NAME.equals(methodDescriptor.getName())) {
                // static variables initialized inside <clinit> save into global static context
                taintConfig.putStaticFieldTaint(classFieldSignature, t);
            } else {
                analyzedMethodConfig.setStaticFieldTaint(classFieldSignature, t);
            }

        } catch (DataflowAnalysisException e) {
        }

        visitPutFieldOp(obj);
    }

    public void visitPutFieldOp(FieldInstruction obj) {

        //int numConsumed = getNumWordsConsumed(obj);
        int numProduced = getNumWordsProduced(obj);
        try {
            Taint t = getFrame().getTopValue();
            handleNormalInstruction(obj);
            notifyAdditionalVisitorField(obj, methodGen, getFrame(), t, numProduced);
        } catch (DataflowAnalysisException e) {

        }

    }

    private void notifyAdditionalVisitorField(FieldInstruction instruction, MethodGen methodGen, TaintFrame frame,
                                              Taint taintValue, int numProduced) {
        for(TaintFrameAdditionalVisitor visitor : visitors) {
            try {
                visitor.visitField(instruction, methodGen, frame, taintValue, numProduced, cpg);
            }
            catch (Throwable e) {
                LOG.log(Level.SEVERE,"Error while executing "+visitor.getClass().getName(),e);
            }
        }
    }

    @Override
    public void visitNEW(NEW obj) {
        ObjectType type = obj.getLoadClassType(cpg);
        Taint taint = TaintFactory.createTaint(type.getSignature(), Taint.State.SAFE);
        taint.setRealInstanceClass(type);
        if (FindSecBugsGlobalConfig.getInstance().isDebugTaintState()) {
            taint.setDebugInfo("new " + type.getClassName() + "()");
        }
        getFrame().pushValue(taint);
    }

    @Override
    public void handleStoreInstruction(StoreInstruction obj) {
        try {
            int numConsumed = obj.consumeStack(cpg);
            if (numConsumed == Const.UNPREDICTABLE) {
                throw new InvalidBytecodeException("Unpredictable stack consumption");
            }
            int index = obj.getIndex();
            while (numConsumed-- > 0) {
//                Taint value = new Taint(getFrame().popValue());
                Taint value = getFrame().popValue().clone();
//                Taint value = getFrame().popValue();
                value.setVariableIndex(index);
                getFrame().setValue(index++, value);
            }
        } catch (DataflowAnalysisException ex) {
            throw new InvalidBytecodeException(ex.toString(), ex);
        }
    }

    @Override
    public void handleLoadInstruction(LoadInstruction load) {
        int numProducedOrig = load.produceStack(cpg);
        int numProduced = numProducedOrig;
        if (numProduced == Const.UNPREDICTABLE) {
            throw new InvalidBytecodeException("Unpredictable stack production");
        }
        int index = load.getIndex() + numProduced;
        while (numProduced-- > 0) {
            Taint value = getFrame().getValue(--index);
            //assert value.hasValidVariableIndex() :
            if(!value.hasValidVariableIndex()) {
                throw new RuntimeException("index not set in " + methodDescriptor);
            }
            if(index != value.getVariableIndex()) {
                throw new RuntimeException("bad index in " + methodDescriptor);
            }
//            getFrame().pushValue(new Taint(value));
            getFrame().pushValue(value);
//            getFrame().pushValue(value.clone());
        }

        for(TaintFrameAdditionalVisitor visitor : visitors) {
            try {
                visitor.visitLoad(load, methodGen, getFrame(), numProducedOrig, cpg);
            }
            catch (Throwable e) {
                LOG.log(Level.SEVERE,"Error while executing "+visitor.getClass().getName(),e);
            }
        }
    }

    @Override
    public void visitINVOKEINTERFACE(INVOKEINTERFACE obj) {
        visitInvoke(obj);
    }

    @Override
    public void visitINVOKESPECIAL(INVOKESPECIAL obj) {
        visitInvoke(obj);
    }

    @Override
    public void visitINVOKESTATIC(INVOKESTATIC obj) {
        visitInvoke(obj);
    }

    @Override
    public void visitINVOKEVIRTUAL(INVOKEVIRTUAL obj) {
        visitInvoke(obj);
    }

    @Override
    public void visitANEWARRAY(ANEWARRAY obj) {
        try {
            getFrame().popValue();
            if (FindSecBugsGlobalConfig.getInstance().isDebugTaintState()) {
                pushSafeDebug("new " + obj.getLoadClassType(cpg).getClassName() + "[]");
            } else {
                getFrame().pushValue(TaintFactory.createTaint(BCELUtil.getSlashedClassName(cpg, obj), Taint.State.SAFE));
            }
        } catch (DataflowAnalysisException ex) {
            throw new InvalidBytecodeException("Array length not in the stack", ex);
        }
    }

    @Override
    public void visitAASTORE(AASTORE obj) {
        try {
            Taint valueTaint = getFrame().popValue(); //Value
            getFrame().popValue(); //Array index
            Taint arrayTaint = getFrame().popValue(); //Array ref

            Taint merge = arrayTaint.merge(valueTaint);
            setLocalVariableTaint(merge, arrayTaint);
            Taint stackTop = null;
            if (getFrame().getStackDepth() > 0) {
                stackTop = getFrame().getTopValue();
            }
            // varargs use duplicated values
            if (arrayTaint.equals(stackTop)) {
                getFrame().popValue();
                getFrame().pushValue(merge.clone());
            }
        } catch (DataflowAnalysisException ex) {
            throw new InvalidBytecodeException("Not enough values on the stack", ex);
        }
    }

    @Override
    public void visitAALOAD(AALOAD obj) {
        try {
            getFrame().popValue(); // array index
            // just transfer the taint from array to value at any index
        } catch (DataflowAnalysisException ex) {
            throw new InvalidBytecodeException("Not enough values on the stack", ex);
        }
    }


    @Override
    public void visitCHECKCAST(CHECKCAST obj) {
        // cast to a safe object type
        ObjectType objectType = obj.getLoadClassType(cpg);
        if (objectType == null) {
            return;
        }

        String objectTypeSignature = objectType.getSignature();

        if(!taintConfig.isClassTaintSafe(objectTypeSignature)) {
            return;
        }

        try {
            getFrame().popValue();
            pushSafe();
        }
        catch (DataflowAnalysisException ex) {
            throw new InvalidBytecodeException("empty stack for checkcast", ex);
        }
    }

    @Override
    public void visitReturnInstruction(ReturnInstruction obj) {
        List<Integer> parametersLocalValueIndexes = new ArrayList<>();

//        LocalVariableGen[] localVariables = methodGen.getLocalVariables();
//        for (LocalVariableGen localVariable : localVariables) {
//            String parameter = localVariable.getType().getSignature();
//
//            switch (parameter.charAt(0)) {

        GenericSignatureParser genericSignatureParser = new GenericSignatureParser(methodDescriptor.getSignature());

        int stackIndex = 0;
        if (!methodDescriptor.isStatic()) {
            parametersLocalValueIndexes.add(0);
            stackIndex++;
        }

        for (Iterator<String> parameterSignatureIterator = genericSignatureParser.parameterSignatureIterator(); parameterSignatureIterator.hasNext();){
            String parameter = parameterSignatureIterator.next();

            switch (parameter.charAt(0)) {
                case 'D':
                case 'J':
                    // double and long occupy two slots
                    stackIndex++;
                    break;
                case '[':
                    // back-propagate array taints
                    parametersLocalValueIndexes.add(stackIndex);
                    break;
                case 'L':
                    // back-propagate mutable class taints
                    if (!taintConfig.isClassImmutable(parameter)) {
                        parametersLocalValueIndexes.add(stackIndex);
                    }
                    else {
                        // back-propage immutable taints only when they transfer tags
                        Taint taint = getFrame().getValue(stackIndex);
                        if (taint.hasTags() || taint.isRemovingTags()) {
                            parametersLocalValueIndexes.add(stackIndex);
                        }
                    }
                    break;
            }

            stackIndex++;
        }

        int stackSize = stackIndex;

        for (int parameterLocalValueIndex : parametersLocalValueIndexes) {
            Taint parameterTaint = getFrame().getValue(parameterLocalValueIndex);
            int parameterIndex = (stackSize - 1) - parameterLocalValueIndex;

            if (!parameterTaint.isUnknown()) {
                analyzedMethodConfig.setParameterOutputTaint(parameterIndex, parameterTaint);
            }
            else if (parameterTaint.getNonParametricState() != Taint.State.INVALID) {
                analyzedMethodConfig.setParameterOutputTaint(parameterIndex, parameterTaint);
            }
            else if (parameterTaint.hasTags() || parameterTaint.isRemovingTags()) {
                analyzedMethodConfig.setParameterOutputTaint(parameterIndex, parameterTaint);
            }
            else if (parameterTaint.getParameters().size() > 1) {
                analyzedMethodConfig.setParameterOutputTaint(parameterIndex, parameterTaint);
            }
            else if (parameterTaint.getFieldTaints() != null) {
                analyzedMethodConfig.setParameterOutputTaint(parameterIndex, parameterTaint);
            }
        }

        // duplicate constructor taint
//        if (parametersLocalValueIndexes.contains(0) && Const.CONSTRUCTOR_NAME.equals(methodDescriptor.getName())) {
//            int stackIndex = (parametersCount - 1) - 0;
//            Map<Integer, Taint> parametersOutputTaints = analyzedMethodConfig.getParametersOutputTaints();
//            Taint constructorTaint = parametersOutputTaints.get(stackIndex);
//            if (constructorTaint != null) {
//                Taint dupConstructorTaint = constructorTaint.clone();
//                analyzedMethodConfig.setParameterOutputTaint(stackIndex + 1, dupConstructorTaint);
//            }
//        }

        analyzedMethodConfig.setParametersOutputTaintsProcessed(true);

        super.visitReturnInstruction(obj);
    }

    @Override
    public void visitARETURN(ARETURN obj) {
        Taint returnTaint = null;
        try {
            returnTaint = getFrame().getTopValue();
            Taint currentTaint = analyzedMethodConfig.getOutputTaint();
            analyzedMethodConfig.setOuputTaint(returnTaint.merge(currentTaint));
        } catch (DataflowAnalysisException ex) {
            throw new InvalidBytecodeException("empty stack before reference return", ex);
        }
        handleNormalInstruction(obj);

        for(TaintFrameAdditionalVisitor visitor : visitors) {
            try {
                visitor.visitReturn(methodGen, returnTaint, cpg);
            }
            catch (Throwable e) {
                LOG.log(Level.SEVERE,"Error while executing "+visitor.getClass().getName(),e);
            }
        }
    }
/*
    @Override
    public void visitRETURN(RETURN obj) {
        // method constructor is void but returns reference
        if (methodDescriptor.getName().equals("<init>")) {
            // first variable is always "this"
            Taint newObjectTaint = getFrame().getValue(0);
            Taint currentTaint = analyzedMethodConfig.getOutputTaint();
            analyzedMethodConfig.setOuputTaint(newObjectTaint.merge(currentTaint));
        }

        handleNormalInstruction(obj);
    }
*/
    /**
     * Regroup the method invocations (INVOKEINTERFACE, INVOKESPECIAL,
     * INVOKESTATIC, INVOKEVIRTUAL)
     *
     * @param obj one of the invoke instructions
     */
    private void visitInvoke(InvokeInstruction obj) {
        assert obj != null;
        try {
            TaintMethodConfig methodConfig = getMethodConfig(obj);
            Taint taint = getMethodTaint(methodConfig);
            if (taint == null) {
                taint = TaintFactory.createTaint(getReturnType(obj.getSignature(cpg)), Taint.State.UNKNOWN);
            }
            assert taint != null;
            if (FindSecBugsGlobalConfig.getInstance().isDebugTaintState()) {
                taint.setDebugInfo(obj.getMethodName(cpg) + "()"); //TODO: Deprecated debug info
            }
            taint.addSource(new UnknownSource(UnknownSourceType.RETURN,taint.getState()).setSignatureMethod(BCELUtil.getSlashedClassName(cpg, obj)+"."+obj.getMethodName(cpg)+obj.getSignature(cpg)));
            taintMutableArguments(methodConfig, obj);
            transferTaintToMutables(methodConfig, taint); // adds variable index to taint too
//            Taint taintCopy = new Taint(taint);
            Taint taintCopy = taint;
            // return type is not always the instance type
            taintCopy.setRealInstanceClass(methodConfig != null && methodConfig.getOutputTaint() != null ? methodConfig.getOutputTaint().getRealInstanceClass() : null);

            TaintFrame tf = getFrame();

            int stackDepth = tf.getStackDepth();
            int nbParam = getNumWordsConsumed(obj);
            List<Taint> parameters = new ArrayList<>(nbParam);
            for(int i=0;i<Math.min(stackDepth,nbParam);i++) {
                parameters.add(tf.getStackValue(i).clone());
            }

            modelInstruction(obj, getNumWordsConsumed(obj), getNumWordsProduced(obj), taintCopy);

            for(TaintFrameAdditionalVisitor visitor : visitors) {
                try {
                    visitor.visitInvoke(obj, methodGen, getFrame() , parameters, cpg);
                }
                catch (Throwable e) {
                    LOG.log(Level.SEVERE,"Error while executing "+visitor.getClass().getName(),e);
                }
            }

        } catch (RuntimeException | DataflowAnalysisException e) {
            String className = ClassName.toSlashedClassName(obj.getReferenceType(cpg).toString());
            String methodName = obj.getMethodName(cpg);
            String signature = obj.getSignature(cpg);

            throw new RuntimeException("Unable to call " + className + '.' + methodName + signature + " in " + methodDescriptor.getSlashedClassName() + "." + methodDescriptor.getName() + methodDescriptor.getSignature(), e);
        }
    }

    private TaintMethodConfig getMethodConfig(InvokeInstruction obj) {
        String signature = obj.getSignature(cpg);
        String returnType = getReturnType(signature);
        String className = getInstanceClassName(obj);
        String methodName = obj.getMethodName(cpg);
        String methodId = "." + methodName + signature;
        TaintMethodConfig config = taintConfig.getMethodConfig(getFrame(), methodDescriptor, className, methodId);
        if (config != null) {
            config = getConfigWithReplaceTags(config, className, methodName);
        }
        if (config != null && config.isConfigured()) {
            return config;
        }
        if (taintConfig.isClassTaintSafe(returnType)) {
            return TaintMethodConfig.SAFE_CONFIG;
        }
        if (config != null) {
            return config;
        }
        String classNameSignature = "L" + className + ";";
        if (Const.CONSTRUCTOR_NAME.equals(methodName)
                && !taintConfig.isClassTaintSafe(classNameSignature)) {
            try {
                int stackSize = getFrame().getNumArgumentsIncludingObjectInstance(obj, cpg);
                config = TaintMethodConfig.getDefaultConstructorConfig(stackSize);
                config.setTypeSignature(className+"<init>()V");
                config.setOuputTaint(TaintFactory.createTaint(classNameSignature, Taint.State.UNKNOWN));
                return config;
            } catch (DataflowAnalysisException ex) {
                throw new InvalidBytecodeException(ex.getMessage(), ex);
            }
        }
        return null;
    }

    private TaintMethodConfig getConfigWithReplaceTags(TaintMethodConfig config, String className, String methodName) {

        ObjectConfiguration objectConfiguration = new ObjectConfiguration(className, methodName);

        if (!objectConfiguration.isAClassThatCanReplaceString()) {
            return config;
        }

        /*
          When Kotlin compiles the String replace method (when using regex values) Kotlin creates several instructions in its place.

          One of the instructions is to create an instance of the Regex class (using the regex String as a parameter). The Regex instance is then used as a parameter to the replace method.
          In order to have access to the regex value when the String replace method is called,
          we need to store the value at the first pass (when the Regex instance is created) and then use it when the replace method is called.

          The below if code is to identify when a Regex instance is being created and store the value, to retrieve on the next pass.

         */
        if (objectConfiguration.isKotlinRegexMethodAndConstructorMethod()) {
            saveRegexValueForNextInstruction();
            return config;
        }

        if (!objectConfiguration.isAReplaceMethod()) {
            return config;
        }

        try {
            String toReplace = objectConfiguration.getStringParameterForReplaceMethod();

            if (toReplace == null) {
                // we don't know the exact value
                return config;
            }

            Taint taint = config.getOutputTaint();

            for (Map.Entry<String, Taint.Tag> replaceTag : REPLACE_TAGS.entrySet()) {
                String tagString = replaceTag.getKey();
                if ((objectConfiguration.isAReplaceMethodWithRegexParameter() && toReplace.contains(tagString))
                        || toReplace.equals(tagString)) {
                    taint.addTag(replaceTag.getValue());
                }
            }

            TaintMethodConfig configCopy = new TaintMethodConfig(config);
            configCopy.setOuputTaint(taint);
            return configCopy;
        } catch (DataflowAnalysisException ex) {
            throw new InvalidBytecodeException(ex.getMessage(), ex);
        }
    }

    private String getRegexValueFromAPreviousInstruction() {
        String tmp = regexValue;
        regexValue = null; // clean up regex value so other instructions after the current one can't use it.
        return tmp;
    }

    private void saveRegexValueForNextInstruction() {
        regexValue = getFrame().getValue(getFrame().getNumSlots() - 1).getConstantValue();
    }

    private String getInstanceClassName(InvokeInstruction invoke) {
        try {
            int instanceIndex = getFrame().getNumArgumentsIncludingObjectInstance(invoke, cpg) - 1;
            if (instanceIndex != -1) {
                assert instanceIndex < getFrame().getStackDepth();
                Taint instanceTaint = getFrame().getStackValue(instanceIndex);
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

    private static String getReturnType(String signature) {
        assert signature != null && signature.contains(")");
        return signature.substring(signature.indexOf(')') + 1);
    }

    private Taint getMethodTaint(TaintMethodConfig methodConfig) {
        if (methodConfig == null || methodConfig.getOutputTaint() == null) {
            return null;
        }
        Taint outputTaint = methodConfig.getOutputTaint();
        assert outputTaint != null;
        assert outputTaint != methodConfig.getOutputTaint() : "defensive copy not made"; // TODO: move assert into tests, unnecessary heap allocation

        Taint taint = mergeTaintWithStack(outputTaint);

        return taint;
    }

    private Taint mergeTaintWithStack(Taint taint) {
        return mergeTaintWithStack(taint, true);
    }

    private Taint mergeTaintWithStack(Taint taint, boolean mergeChildren) {
        assert taint != null;
        Taint result = taint;

        boolean mergedWithStack = false;
        if (taint.isUnresolved()) {
            result = null;

            // taint consisting of merged parameters only
            if (taint.hasParameters()) {
                Taint transferParametersTaint = mergeTransferParameters(taint.getParameters());
                assert transferParametersTaint != null;

                result = transferParametersTaint;
            }

            // taint depends on fields
            if (taint.hasFields()) {
                Taint transferFieldsTaint = mergeTransferFields(taint.getFields());
                assert transferFieldsTaint != null;

                result = transferFieldsTaint.merge(result);
            }

            // taint depends on static fields
            if (taint.hasStaticFields()) {
                Taint transferStaticFieldsTaint = mergeStaticTransferFields(taint.getStaticFields());
                assert transferStaticFieldsTaint != null;

                result = transferStaticFieldsTaint.merge(result);
            }

            assert result != null;

            if (taint.getNonParametricState() != Taint.State.INVALID) {
                // if the method body has own inner state then merge with parameters
                result = result.merge(Taint.valueOf(taint.getNonParametricState()));
            }

            result.addAllSources(taint.getSources());

            // merge removes tags so we made a taint copy before
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

        if (result.isTainted()) {
            result.addLocation(getTaintLocation(), true);
        }
        else if (result.isUnknown() || result.isUnresolved()) {
            result.addLocation(getTaintLocation(), false);
        }

        // merge taint class fields with stack
        if (mergeChildren && taint.getFieldTaints() != null) {
            for (Map.Entry<String, Taint> fieldTaintEntry : taint.getFieldTaints().entrySet()) {
                String fieldName = fieldTaintEntry.getKey();
                Taint fieldTaint = fieldTaintEntry.getValue();

                // apply stack to the field taint
                Taint mergedTaint = mergeTaintWithStack(fieldTaint);

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

                if (mergedTaint.isTainted()) {
                    mergedTaint.addLocation(getTaintLocation(), true);
                }
                else if (mergedTaint.isUnknown() || mergedTaint.isUnresolved()) {
                    mergedTaint.addLocation(getTaintLocation(), false);
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

    private void taintMutableArguments(TaintMethodConfig methodConfig, InvokeInstruction obj) {
        if (methodConfig != null && methodConfig.isConfigured()) {
            return;
        }

        if (methodConfig != null && methodConfig.isParametersOutputTaintsProcessed()) {
            Map<Integer, Taint> parametersOutputTaints = methodConfig.getParametersOutputTaints();

            boolean isConstructor = methodConfig.getTypeSignature().contains("<init>");
            try {
                int instanceStackLocation = getFrame().getInstanceStackLocation(obj, cpg);

                for (Map.Entry<Integer, Taint> entry : parametersOutputTaints.entrySet()) {
                    int stackIndex = entry.getKey();
                    assert stackIndex >= 0 && stackIndex < getFrame().getStackDepth();

                    Taint parameterTaint = entry.getValue();
                    assert parameterTaint != null;

                    Taint taint = parameterTaint.clone();
                    taint = mergeTaintWithStack(taint);

                    Taint stackValue = getFrame().getStackValue(stackIndex);
                    taint = taint.merge(stackValue);

                    // don't add tags to safe values
                    if (!taint.isSafe() && parameterTaint.hasTags()) {
                        for (Taint.Tag tag : parameterTaint.getTags()) {
                            taint.addTag(tag);
                        }
                    }
                    if (parameterTaint.isRemovingTags()) {
                        for (Taint.Tag tag : parameterTaint.getTagsToRemove()) {
                            taint.removeTag(tag);
                        }
                    }

                    if (stackValue.hasValidVariableIndex()) {
                        taint.setVariableIndex(stackValue.getVariableIndex());
                    } else {
                        // invalidate the variable index, taint comes from a different method
                        taint.invalidateVariableIndex();
                    }
                    taint.setRealInstanceClass(stackValue.getRealInstanceClass());
                    getFrame().setValue(getFrame().getStackLocation(stackIndex), taint);
                    setLocalVariableTaint(taint, stackValue);

                    // invoking a constructor creates 2 stack items (one consumed by the invoke instruction and one as the <init> result)
                    if (isConstructor && instanceStackLocation == stackIndex) {
                        int dupStackIndex = stackIndex + 1;
                        if (dupStackIndex < getFrame().getStackDepth()) {
                            getFrame().setValue(getFrame().getStackLocation(dupStackIndex), taint);
                        }
                    }
                }
            } catch (DataflowAnalysisException e) {
                e.printStackTrace();
            }


            return;
        }
        // TODO: review (defaultValue(), locations)
        Collection<Integer> mutableStackIndices = getMutableStackIndices(obj.getSignature(cpg));
        for (Integer index : mutableStackIndices) {
            assert index >= 0 && index < getFrame().getStackDepth();
            try {
                Taint stackValue = getFrame().getStackValue(index);
                Taint taint = stackValue.merge(getDefaultValue());
                if (stackValue.hasValidVariableIndex()) {
                    // set back the index removed during merging
                    taint.setVariableIndex(stackValue.getVariableIndex());
                }
                taint.setRealInstanceClass(stackValue.getRealInstanceClass());
                taint.addLocation(getTaintLocation(), false);
                getFrame().setValue(getFrame().getStackLocation(index), taint);
                setLocalVariableTaint(taint, taint);
            } catch (DataflowAnalysisException ex) {
                throw new InvalidBytecodeException("Not enough values on the stack", ex);
            }
        }
    }

    private Taint mergeTransferParameters(Collection<Integer> transferParameters) {
        assert transferParameters != null && !transferParameters.isEmpty();
        Taint taint = null;
        Taint safeTaint = null;
        for (Integer transferParameter : transferParameters) {
            try {
                Taint value = getFrame().getStackValue(transferParameter);
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


    private Taint mergeTransferFields(Collection<Taint.FieldTuple> transferFields) {
        assert transferFields != null && !transferFields.isEmpty();
        Taint taint = null;
        Taint safeTaint = null;
        for (Taint.FieldTuple transferField : transferFields) {
            Taint parentTaint = transferField.getParentTaint();

            parentTaint = mergeTaintWithStack(parentTaint, false);

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

    private Taint mergeStaticTransferFields(Set<ClassFieldSignature> transferStaticFields) {
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

    private void transferTaintToMutables(TaintMethodConfig methodConfig, Taint taint) {
        assert taint != null;
        if (methodConfig == null || !methodConfig.hasMutableStackIndices()) {
            return;
        }
        try {
            int stackDepth = getFrame().getStackDepth();
            for (Integer mutableStackIndex : methodConfig.getMutableStackIndices()) {
                assert mutableStackIndex >= 0;
                if (mutableStackIndex >= stackDepth) {
                    if (!Const.CONSTRUCTOR_NAME.equals(methodDescriptor.getName())
                            && !Const.STATIC_INITIALIZER_NAME.equals(methodDescriptor.getName())) {
                        assert false : "Out of bounds mutables in " + methodDescriptor + " Method Config: " + methodConfig.toString();
                    }
                    continue; // ignore if assertions disabled or if in constructor
                }
                Taint stackValue = getFrame().getStackValue(mutableStackIndex);
                setLocalVariableTaint(taint, stackValue);
                Taint taintCopy = taint.clone();
                // do not set instance to return values, can be different type
                taintCopy.setRealInstanceClass(stackValue.getRealInstanceClass());
                getFrame().setValue(getFrame().getStackLocation(mutableStackIndex), taintCopy);
            }
        } catch (DataflowAnalysisException ex) {
            assert false : ex.getMessage(); // stack depth is checked
        }
    }

    private void setLocalVariableTaint(Taint valueTaint, Taint indexTaint) {
        assert valueTaint != null && indexTaint != null;
        if (!indexTaint.hasValidVariableIndex()) {
            return;
        }
        int index = indexTaint.getVariableIndex();
        if (index >= getFrame().getNumLocals()) {
            assert false : "Out of bounds local variable index in " + methodDescriptor;
            return; // ignore if assertions disabled
        }

        if (valueTaint.hasValidVariableIndex() && valueTaint.getVariableIndex() != index) {
            valueTaint = valueTaint.clone();
        }

        valueTaint.setVariableIndex(index);
        getFrame().setValue(index, valueTaint);
    }

    /**
     * Push a value to the stack
     */
    private void pushSafe() {
        getFrame().pushValue(TaintFactory.createTaint(Taint.State.SAFE));
    }

    /**
     * Push a value to the stack
     * The information passed will be viewable when the stack will be print. (See printStackState())
     * @param debugInfo String representation of the value push
     */
    private void pushSafeDebug(String debugInfo) {
        getFrame().pushValue(TaintFactory.createTaint(Taint.State.SAFE).setDebugInfo(debugInfo));
    }

    private TaintLocation getTaintLocation() {
        return new TaintLocation(methodDescriptor, getLocation().getHandle().getPosition());
    }

    /**
     * This method must be called from outside at the end of the method analysis
     */
    public void finishAnalysis() {
        assert analyzedMethodConfig != null;
        Taint outputTaint = analyzedMethodConfig.getOutputTaint();
        if (outputTaint != null) {
            String returnType = getReturnType(methodDescriptor.getSignature());
            String realInstanceClassName = outputTaint.getRealInstanceClassName();
            if (returnType.equals("L" + realInstanceClassName + ";")) {
                // storing it in method summary is useless
                outputTaint.setRealInstanceClass(null);
                analyzedMethodConfig.setOuputTaint(outputTaint);
            }
        }
        String className = methodDescriptor.getSlashedClassName();
        String methodId = "." + methodDescriptor.getName() + methodDescriptor.getSignature();
        if (analyzedMethodConfig.isInformative()
                || taintConfig.getSuperMethodConfig(className, methodId) != null) {
            String fullMethodName = className.concat(methodId);
            if (!taintConfig.containsKey(fullMethodName)) {
                // prefer configured summaries to derived
                taintConfig.put(fullMethodName, analyzedMethodConfig);
//                System.out.println("@@@@ PUT: " + fullMethodName + " with: " + analyzedMethodConfig);
            }
        }
    }

    private class ObjectConfiguration {

        private static final int JAVA_STRING_PARAMETER_INDEX = 1;
        private static final int KOTLIN_STRING_PARAMETER_INDEX = 4;

        private final String className;
        private final String methodName;

        private ObjectConfiguration(String className, String methodName) {
            this.className = className;
            this.methodName = methodName;
        }

        private boolean isJavaString() {
            return "java/lang/String".equals(className);
        }

        private boolean isKotlinString() {
            return "kotlin/text/StringsKt".equals(className);
        }

        private boolean isKotlinRegex() {
            return "kotlin/text/Regex".equals(className);
        }

        private boolean isConstructor() {
            return Const.CONSTRUCTOR_NAME.equals(methodName);
        }

        private boolean isKotlinRegexMethodAndConstructorMethod() {
            return isKotlinRegex() && isConstructor();
        }

        private boolean isJavaStringWithSimpleReplace() {
            return isJavaString() && "replace".equals(methodName);
        }

        private boolean isKotlinStringWithSimpleReplace() {
            return isKotlinString() && "replace$default".equals(methodName);
        }

        private boolean isJavaStringWithRegexReplace() {
            return isJavaString() && "replaceAll".equals(methodName);
        }

        private boolean isKotlinRegexWithReplace() {
            return isKotlinRegex() && "replace".equals(methodName);
        }

        private boolean isAClassThatCanReplaceString() {
            return isJavaString() || isKotlinString() || isKotlinRegex();
        }

        private boolean isAReplaceMethod() {
            return isJavaStringWithRegexReplace() || isKotlinRegexWithReplace() || isJavaStringWithSimpleReplace() || isKotlinStringWithSimpleReplace();
        }

        private boolean isAReplaceMethodWithRegexParameter() {
            return isJavaStringWithRegexReplace() || isKotlinRegexWithReplace();
        }

        private String getStringParameterForReplaceMethod() throws DataflowAnalysisException {

            if (isJavaString()) {
                return getFrame().getStackValue(JAVA_STRING_PARAMETER_INDEX).getConstantValue();
            } else if (isKotlinString()) {
                return getFrame().getStackValue(KOTLIN_STRING_PARAMETER_INDEX).getConstantValue();
            } else if (isKotlinRegexWithReplace()) {
                return getRegexValueFromAPreviousInstruction();
            }

            return null;
        }
    }

}
