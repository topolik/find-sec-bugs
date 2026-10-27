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

import edu.umd.cs.findbugs.SystemProperties;

/**
 * This class contains some flag that can be used to create global configuration.
 * This could be use to have alternative behavior if the command line client is used versus the usual FindBugs
 * environment.
 */
public class FindSecBugsGlobalConfig {

    private static final FindSecBugsGlobalConfig instance = new FindSecBugsGlobalConfig();

    private String findSecBugsVersion = "1.6.0";
    private boolean debugPrintInstructionVisited = false;
    private boolean debugPrintInvocationVisited = false;
    private boolean debugTaintState = false;
    private boolean workaroundVisitInvokeDynamic = false;
    private boolean verboseLocationReport = false;
    
    // set through SystemProperties
    private boolean debugOutputTaintConfigs;
    private boolean taintedSystemVariables;
    private String customConfigFile;
    private boolean taintedMainArgument;
    private boolean reportPotentialXssWrongContext;
    private String taintConfigUsage;
    private String taintConfigUsageFile;
    private String taintExcludeConfigKeys;
    private String taintImportConfigFile;
    private boolean taintOverriders;
    private String taintDistrustDerived;
    private String taintDistrustDerivedFile;
    private int taintDistrustDerivedMaxMerged;
    private String taintOverridersFile;
    private boolean taintPrepass;

    protected FindSecBugsGlobalConfig() {
        debugOutputTaintConfigs = Boolean.parseBoolean(loadFromSystem("findsecbugs.taint.outputconfigs", Boolean.FALSE.toString()));
        taintedSystemVariables = Boolean.parseBoolean(loadFromSystem("findsecbugs.taint.taintedsystemvariables", Boolean.FALSE.toString()));
        customConfigFile = loadFromSystem("findsecbugs.taint.customconfigfile", null);
        taintedMainArgument = Boolean.parseBoolean(loadFromSystem("findsecbugs.taint.taintedmainargument", Boolean.TRUE.toString()));
        reportPotentialXssWrongContext = Boolean.parseBoolean(loadFromSystem("findsecbugs.taint.reportpotentialxsswrongcontext", Boolean.FALSE.toString()));
        debugTaintState = Boolean.parseBoolean(loadFromSystem("findsecbugs.taint.debugtaintstate", Boolean.FALSE.toString()));
        workaroundVisitInvokeDynamic = Boolean.parseBoolean(loadFromSystem("findsecbugs.taint.workaroundvisitinvokedynamic", Boolean.FALSE.toString()));
        verboseLocationReport = Boolean.parseBoolean(loadFromSystem("findsecbugs.taint.verboselocationreport", Boolean.FALSE.toString()));
        taintConfigUsage = loadFromSystem("findsecbugs.taint.configusage", null);
        taintConfigUsageFile = loadFromSystem("findsecbugs.taint.configusagefile", "config-usage.txt");
        taintExcludeConfigKeys = loadFromSystem("findsecbugs.taint.excludeconfigkeys", null);
        taintImportConfigFile = loadFromSystem("findsecbugs.taint.importconfigfile", null);
        taintOverriders = Boolean.parseBoolean(loadFromSystem("findsecbugs.taint.overriders", Boolean.FALSE.toString()));
        taintDistrustDerived = loadFromSystem("findsecbugs.taint.distrustderived", "merge,implementors");
        taintDistrustDerivedFile = loadFromSystem("findsecbugs.taint.distrustderivedfile", null);
        taintDistrustDerivedMaxMerged = Integer.parseInt(loadFromSystem("findsecbugs.taint.distrustderivedmaxmerged", "16"));
        taintOverridersFile = loadFromSystem("findsecbugs.taint.overridersfile", null);
        taintPrepass = Boolean.parseBoolean(loadFromSystem("findsecbugs.taint.prepass", Boolean.TRUE.toString()));
    }

    public String loadFromSystem(String key, String defaultValue) {
        String value = System.getenv(key);
        if (value == null) {
            // Environment variables containing dots are difficult to setup in
            // bash. Thus also accept underscores instead of dots.
            value = System.getenv(key.replace('.', '_'));
        }
        value = SystemProperties.getProperty(key, value);

        if (value == null) {
            return defaultValue;
        }

        return value;
    }

    /**
     * This getter will load sink injections.
     *
     * TODO: Load dynamically all system variable with the prefix in the constructor.
     * @param suffix
     * @return
     */
    public String getCustomSinksConfigFile(String suffix) {
        return loadFromSystem("findsecbugs.injection.customconfigfile." + suffix, null);
    }

    public static FindSecBugsGlobalConfig getInstance() {
        return instance;
    }

    /*** Getters and setters only **/

    public String getFindSecBugsVersion() {
        return findSecBugsVersion;
    }

    public void setFindSecBugsVersion(String findSecBugsVersion) {
        this.findSecBugsVersion = findSecBugsVersion;
    }

    public boolean isDebugOutputTaintConfigs() {
        return debugOutputTaintConfigs;
    }

    public boolean isWorkaroundVisitInvokeDynamic() {
        return workaroundVisitInvokeDynamic;
    }

    public void setWorkaroundVisitInvokeDynamic(boolean workaroundVisitInvokeDynamic) {
        this.workaroundVisitInvokeDynamic = workaroundVisitInvokeDynamic;
    }

    public boolean isVerboseLocationReport() {
        return verboseLocationReport;
    }

    public void setDebugOutputTaintConfigs(boolean debugOutputTaintConfigs) {
        this.debugOutputTaintConfigs = debugOutputTaintConfigs;
    }

    public boolean isDebugPrintInstructionVisited() {
        return debugPrintInstructionVisited;
    }

    public void setDebugPrintInstructionVisited(boolean debugPrintInstructionVisited) {
        this.debugPrintInstructionVisited = debugPrintInstructionVisited;
    }

    public boolean isDebugPrintInvocationVisited() {
        return debugPrintInvocationVisited;
    }

    public void setDebugPrintInvocationVisited(boolean debugPrintInvocationVisited) {
        this.debugPrintInvocationVisited = debugPrintInvocationVisited;
    }

    public boolean isDebugTaintState() {
        return debugTaintState;
    }

    public void setDebugTaintState(boolean debugTaintState) {
        this.debugTaintState = debugTaintState;
    }

    public boolean isTaintedSystemVariables() {
        return taintedSystemVariables;
    }

    public void setTaintedSystemVariables(boolean taintedSystemVariables) {
        this.taintedSystemVariables = taintedSystemVariables;
    }

    public String getCustomConfigFile() {
        return customConfigFile;
    }

    public void setCustomConfigFile(String customConfigFile) {
        this.customConfigFile = customConfigFile;
    }

    public boolean isTaintedMainArgument() {
        return taintedMainArgument;
    }

    public void setTaintedMainArgument(boolean taintedMainArguments) {
        this.taintedMainArgument = taintedMainArguments;
    }

    /**
     * Whether the usage of the custom taint config entries is recorded,
     * "true" writes the used entries only, "all" writes every custom entry
     */
    public boolean isTaintConfigUsage() {
        return "true".equalsIgnoreCase(taintConfigUsage) || isTaintConfigUsageAll();
    }

    public boolean isTaintConfigUsageAll() {
        return "all".equalsIgnoreCase(taintConfigUsage);
    }

    public void setTaintConfigUsage(String taintConfigUsage) {
        this.taintConfigUsage = taintConfigUsage;
    }

    public String getTaintConfigUsageFile() {
        return taintConfigUsageFile;
    }

    public void setTaintConfigUsageFile(String taintConfigUsageFile) {
        this.taintConfigUsageFile = taintConfigUsageFile;
    }

    /**
     * File listing the keys dropped from the custom taint configs, one key per line
     */
    public String getTaintExcludeConfigKeys() {
        return taintExcludeConfigKeys;
    }

    public void setTaintExcludeConfigKeys(String taintExcludeConfigKeys) {
        this.taintExcludeConfigKeys = taintExcludeConfigKeys;
    }

    /**
     * Files of summaries derived by other scans (derived-config.txt format) imported for the methods
     * without a summary, separated by the path separator
     */
    public String getTaintImportConfigFile() {
        return taintImportConfigFile;
    }

    public void setTaintImportConfigFile(String taintImportConfigFile) {
        this.taintImportConfigFile = taintImportConfigFile;
    }

    /**
     * Apply the summaries of the overriding methods to the calls: enables {@link #getTaintDistrustDerived},
     * {@link #getTaintOverridersFile} and {@link #isTaintPrepass}. Disabled by default: scanning one
     * module at a time, the abstract methods merge only the implementors the module knows, and the
     * implementors of the other modules pay off only with their summaries imported, see
     * {@link #getTaintImportConfigFile}
     */
    public boolean isTaintOverriders() {
        return taintOverriders;
    }

    public void setTaintOverriders(boolean taintOverriders) {
        this.taintOverriders = taintOverriders;
    }

    /**
     * Kinds of derived summaries not applied to the calls, separated by commas: {@code override} for
     * the methods declared by a known subtype of the receiver class, {@code merge} to apply the summary
     * merged with the summaries of the subtypes instead, {@code implementors} to apply the summaries
     * of the subtypes merged to the abstract methods, {@code constructor} for the constructed object.
     * Applies only with {@link #isTaintOverriders}. Defaults to {@code merge,implementors}, {@code none}
     * or an empty value applies all derived summaries
     */
    public String getTaintDistrustDerived() {
        return taintDistrustDerived;
    }

    public void setTaintDistrustDerived(String taintDistrustDerived) {
        this.taintDistrustDerived = taintDistrustDerived;
    }

    /**
     * File listing the distrusted derived summaries with their overriders
     */
    public String getTaintDistrustDerivedFile() {
        return taintDistrustDerivedFile;
    }

    public void setTaintDistrustDerivedFile(String taintDistrustDerivedFile) {
        this.taintDistrustDerivedFile = taintDistrustDerivedFile;
    }

    /**
     * Maximum number of subtypes whose summaries are merged with the summary of the receiver class
     */
    public int getTaintDistrustDerivedMaxMerged() {
        return taintDistrustDerivedMaxMerged;
    }

    public void setTaintDistrustDerivedMaxMerged(int taintDistrustDerivedMaxMerged) {
        this.taintDistrustDerivedMaxMerged = taintDistrustDerivedMaxMerged;
    }

    /**
     * Files listing the subtypes declaring the methods of the classes outside the analyzed code,
     * separated by the path separator, see {@link com.h3xstream.findsecbugs.taintanalysis.TaintConfig#loadOverriders}.
     * Applies only with {@link #isTaintOverriders}
     */
    public String getTaintOverridersFile() {
        return taintOverridersFile;
    }

    public void setTaintOverridersFile(String taintOverridersFile) {
        this.taintOverridersFile = taintOverridersFile;
    }

    /**
     * Derive the summaries of all analyzed classes before the detectors run, so the summaries of the
     * classes analyzed later, such as the overriding methods merged by {@link #getTaintDistrustDerived},
     * are known at the call sites. Applies only with {@link #isTaintOverriders}, enabled by default
     */
    public boolean isTaintPrepass() {
        return taintPrepass;
    }

    public void setTaintPrepass(boolean taintPrepass) {
        this.taintPrepass = taintPrepass;
    }

    public boolean isReportPotentialXssWrongContext() {
        return reportPotentialXssWrongContext;
    }

    public void setReportPotentialXssWrongContext(boolean reportPotentialXssWrongContext) {
        this.reportPotentialXssWrongContext = reportPotentialXssWrongContext;
    }
}
