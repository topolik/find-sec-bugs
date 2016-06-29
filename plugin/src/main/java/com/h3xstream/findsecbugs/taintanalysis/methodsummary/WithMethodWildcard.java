package com.h3xstream.findsecbugs.taintanalysis.methodsummary;

import com.h3xstream.findsecbugs.taintanalysis.TaintFrameModelingVisitor;

import java.util.regex.Pattern;

/**
 * @author Tomas Polesovsky
 */
public class WithMethodWildcard implements TaintMethodSummaryParser {
	private static final Pattern methodSyntax;
	static {
		// com/company/Constants.*(*)*
		String methodWildcardsWithClassNameRegex = classWithPackageRegex + Pattern.quote(".*(*)*");
		methodSyntax = Pattern.compile(methodWildcardsWithClassNameRegex);
	}

	@Override
	public boolean accepts(String methodFullName) {
		return methodSyntax.matcher(methodFullName).matches();
	}

	@Override
	public String parse(String className, String methodName, String signature, TaintFrameModelingVisitor taintFrameModelingVisitor) {
		// Matches all methods of a class
		// Example: com/company/Constants.*(*)*:SAFE
		return className + ".*(*)*";
	}
}
