package com.h3xstream.findsecbugs.taintanalysis.taint;

import com.h3xstream.findsecbugs.taintanalysis.Taint;

/**
 * @author Tomas Polesovsky
 */
public class TaintFactory {
    public static Taint createTaint(Taint.State initState) {
        return createTaint(null, initState);
    }

    public static Taint createTaint(String typeSignature, Taint.State initState) {
        if (typeSignature == null || typeSignature.length() == 0) {
            return new Taint(initState);
        }

        if (typeSignature.charAt(0) == 'L') {
            return new ObjectTaint(typeSignature, initState);
        }

        if (typeSignature.charAt(0) == '[') {
            return new ArrayTaint(initState);
        }

        return new Taint(initState);
    }
}
