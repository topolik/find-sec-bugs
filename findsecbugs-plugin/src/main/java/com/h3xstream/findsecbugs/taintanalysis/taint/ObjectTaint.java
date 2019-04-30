package com.h3xstream.findsecbugs.taintanalysis.taint;

import com.h3xstream.findsecbugs.taintanalysis.Taint;
import com.h3xstream.findsecbugs.taintanalysis.TaintConfig;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * @author Tomas Polesovsky
 */
public class ObjectTaint extends Taint {

    public ObjectTaint(String signature, State state) {
        super(state);
        typeSignature = signature;
    }

    public ObjectTaint(String signature, Taint taint) {
        super(taint);
        typeSignature = signature;
    }

    public ObjectTaint setFieldTaint(String field, Taint fieldTaint) {
        if (fieldTaints == null) {
            fieldTaints = new HashMap<>();
        }

        fieldTaints.put(field, fieldTaint);

        return this;
    }

    public Taint getFieldTaint(String fieldName, String fieldSignature, TaintConfig taintConfig) {
        if (fieldTaints != null) {
            Taint taint = fieldTaints.get(fieldName);
            if (taint != null) {
                return taint;
            }
        }

        String fullFieldName = typeSignature.substring(1, typeSignature.length()-1) + "." +fieldName;

        Taint.State state = taintConfig.getClassTaintState(fullFieldName, Taint.State.UNKNOWN);

        Taint taint = TaintFactory.createTaint(fieldSignature, state);
        setFieldTaint(fieldName, taint);
        return taint;
    }

    public String getTypeSignature() {
        return typeSignature;
    }

    private Map<String, Taint> fieldTaints;
    private String typeSignature;

    @Override
    public Taint clone() {
        ObjectTaint clone = new ObjectTaint(typeSignature, this);
        if (fieldTaints != null) {
            clone.fieldTaints = new HashMap<>(fieldTaints.size());

            fieldTaints.forEach((fieldName, taint) -> clone.fieldTaints.put(fieldName, taint.clone()));
        }

        return clone;
    }

    @Override
    public Taint merge(Taint b) {
        if (b == null) {
            return clone();
        }

        if (!ObjectTaint.class.isInstance(b)) {
            //TODO
            System.out.println("Merging different kinds of taints! " + this + " and " + b);
            return b.merge(this);
        }

        if (!Objects.equals(typeSignature, ((ObjectTaint) b).typeSignature)) {
            //TODO
            System.out.println("Merging different kinds of taints! " + this + " and " + b);
            return super.merge(b);
        }

        ObjectTaint objectTaintA = (ObjectTaint) super.merge(b);
        ObjectTaint objectTaintB = (ObjectTaint) b;

        if (objectTaintB.fieldTaints != null) {
            if (objectTaintA.fieldTaints == null) {
                objectTaintA.fieldTaints = new HashMap<>(objectTaintB.fieldTaints.size());
            }

            for (Map.Entry<String, Taint> entry : objectTaintB.fieldTaints.entrySet()) {
                objectTaintA.fieldTaints.compute(entry.getKey(), (__, v) -> entry.getValue().merge(v));
            }
        }

        return objectTaintA;
    }

    @Override
    public boolean isInformative() {
        if(super.isInformative()) {
            return true;
        }

        if (fieldTaints != null) {
            for (Taint taint : fieldTaints.values()) {
                if (taint.isInformative()) {
                    return true;
                }
            }
        }

        return false;
    }

    @Override
    public String toString() {
        return new StringBuffer(7)
                .append(" typeSignature={").append(typeSignature).append("}")
                .append(' ').append(super.toString())
                .append(" fieldTaints={").append(fieldTaints).append("}")
                .toString();
    }
}
