package com.h3xstream.findsecbugs.taintanalysis.taint;

import com.h3xstream.findsecbugs.taintanalysis.Taint;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Tomas Polesovsky
 */
public class ArrayTaint extends Taint {
    Map<Integer, Taint> context;

    public ArrayTaint(State state) {
        super(state);
    }

    public ArrayTaint(Taint taint) {
        super(taint);
    }

    @Override
    public ArrayTaint clone() {
        return new ArrayTaint(super.clone());
    }

    public void set(Taint valueTaint, int pos) {
        if (context == null) {
            context = new HashMap<>();
        }

        context.put(pos, valueTaint);
    }

    public Taint get(int pos) {
        if (context == null) {
            return null;
        }

        return context.get(pos);
    }
}
