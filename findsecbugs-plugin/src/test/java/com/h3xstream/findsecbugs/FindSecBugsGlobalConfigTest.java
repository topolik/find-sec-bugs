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
package com.h3xstream.findsecbugs;

import com.h3xstream.findsecbugs.taintanalysis.TaintConfig;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class FindSecBugsGlobalConfigTest {

    @Test
    public void version() {
        FindSecBugsGlobalConfig.getInstance().setFindSecBugsVersion("1.3.3.7");
        assertEquals(FindSecBugsGlobalConfig.getInstance().getFindSecBugsVersion(),"1.3.3.7");
    }

    @Test
    public void derivedSummariesDefaults() {
        FindSecBugsGlobalConfig config = new FindSecBugsGlobalConfig();
        assertTrue(config.isTaintPrepass());
        assertEquals(config.getTaintDistrustDerived(), "merge,implementors");

        TaintConfig taintConfig = new TaintConfig();
        taintConfig.setDistrustedDerived(config.getTaintDistrustDerived());
        assertTrue(taintConfig.isDistrustingDerivedOverrides());
        assertTrue(taintConfig.isMergingDerivedOverrides());
        assertTrue(taintConfig.isMergingImplementors());
        assertFalse(taintConfig.isDistrustingDerivedConstructors());
    }

    @Test
    public void derivedSummariesOptOut() {
        for (String kinds : new String[] {"none", ""}) {
            TaintConfig taintConfig = new TaintConfig();
            taintConfig.setDistrustedDerived("merge,implementors,constructor");
            taintConfig.setDistrustedDerived(kinds);
            assertFalse(taintConfig.isDistrustingDerivedOverrides(), kinds);
            assertFalse(taintConfig.isMergingDerivedOverrides(), kinds);
            assertFalse(taintConfig.isMergingImplementors(), kinds);
            assertFalse(taintConfig.isDistrustingDerivedConstructors(), kinds);
        }
    }

}
