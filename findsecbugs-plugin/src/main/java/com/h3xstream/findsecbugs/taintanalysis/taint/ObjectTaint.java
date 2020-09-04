package com.h3xstream.findsecbugs.taintanalysis.taint;

import com.h3xstream.findsecbugs.BCELUtil;
import com.h3xstream.findsecbugs.taintanalysis.Taint;
import com.h3xstream.findsecbugs.taintanalysis.TaintConfig;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * @author Tomas Polesovsky
 */
public class ObjectTaint extends Taint {

    public ObjectTaint(State state) {
        super(state);
    }

    public ObjectTaint(Taint taint) {
        super(taint);
    }

}
