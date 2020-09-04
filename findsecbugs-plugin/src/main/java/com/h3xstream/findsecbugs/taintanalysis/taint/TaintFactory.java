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
        Taint result = null;

        if (typeSignature == null || typeSignature.length() == 0) {
            result = new Taint(initState);
        }
        else if (typeSignature.charAt(0) == '[') {
            result = new ArrayTaint(initState);
        }
        else {
            result = new Taint(initState);
        }

        result.setTypeSignature(typeSignature);

        return result;
    }
}
