package com.h3xstream.findsecbugs.taintanalysis.methodsummary;

import com.h3xstream.findsecbugs.taintanalysis.TaintFrameModelingVisitor;

/**
 * @author Tomas Polesovsky
 */
public interface TaintMethodSummaryParser {
	static final String classWithPackageRegex = "([a-z][a-z0-9]*\\/)*[A-Z][a-zA-Z0-9\\$]*";
	static final String typeRegex = "(\\[)*((L" + classWithPackageRegex + ";)|B|C|D|F|I|J|S|Z)";
	static final String returnRegex = "(V|(" + typeRegex + "))";
	static final String methodRegex = "(([a-zA-Z][a-zA-Z0-9]*)|(<init>))";
	static final String signatureRegex = "\\((" + typeRegex + ")*\\)" + returnRegex;

	boolean accepts(String methodFullName);

	String parse(String className, String methodName, String signature, TaintFrameModelingVisitor taintFrameModelingVisitor);
}
