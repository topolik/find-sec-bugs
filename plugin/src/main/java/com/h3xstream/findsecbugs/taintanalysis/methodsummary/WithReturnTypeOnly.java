package com.h3xstream.findsecbugs.taintanalysis.methodsummary;

import com.h3xstream.findsecbugs.taintanalysis.TaintFrameModelingVisitor;

import java.util.regex.Pattern;

/**
 * @author Tomas Polesovsky
 */
public class WithReturnTypeOnly implements TaintMethodSummaryParser {
	private static final Pattern methodSyntax;

	static {
		// *.*(*)Lcom/company/ConstantEnum;:SAFE
		String methodWildcardsWithReturnTypeRegex = Pattern.quote("*.*(*)") + returnRegex;
		methodSyntax = Pattern.compile(methodWildcardsWithReturnTypeRegex);
	}

	@Override
	public boolean accepts(String methodFullName) {
		return methodSyntax.matcher(methodFullName).matches();
	}

	@Override
	public String parse(String className, String methodName, String signature, TaintFrameModelingVisitor taintFrameModelingVisitor) {
		String returnType = getReturnType(signature);

		// Matches specific return type
		// Example: *.*(*)Lcom/company/ConstantEnum;:SAFE
		return "*.*(*)" + returnType;
	}

	private static String getReturnType(String signature) {
		assert signature != null && signature.contains(")");
		return signature.substring(signature.indexOf(')') + 1);
	}
}
