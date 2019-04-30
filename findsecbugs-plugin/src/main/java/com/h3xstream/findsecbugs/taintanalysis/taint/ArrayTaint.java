package com.h3xstream.findsecbugs.taintanalysis.taint;

import com.h3xstream.findsecbugs.taintanalysis.Taint;

/**
 * @author Tomas Polesovsky
 */
public class ArrayTaint extends Taint {

    public ArrayTaint(State state) {
        super(state);
    }

    public ArrayTaint(Taint taint) {
        super(taint);
    }
}
