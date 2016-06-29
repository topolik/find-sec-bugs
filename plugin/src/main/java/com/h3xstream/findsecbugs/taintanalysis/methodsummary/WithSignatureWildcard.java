package com.h3xstream.findsecbugs.taintanalysis.methodsummary;

import com.h3xstream.findsecbugs.taintanalysis.TaintFrameModelingVisitor;

import java.util.regex.Pattern;

/**
 * @author Tomas Polesovsky
 */
public class WithSignatureWildcard implements TaintMethodSummaryParser {
	private static final Pattern methodSyntax;
	static {
		// java/sql/ResultSet.getString(*)*
		String methodWildardsWithClassAndMethodRegex = classWithPackageRegex + "\\." + methodRegex + Pattern.quote("(*)*");
		methodSyntax = Pattern.compile(methodWildardsWithClassAndMethodRegex);
	}

	@Override
	public boolean accepts(String methodFullName) {
		return methodSyntax.matcher(methodFullName).matches();
	}

	@Override
	public String parse(String className, String methodName, String signature, TaintFrameModelingVisitor taintFrameModelingVisitor) {
		// Matches all methods with specified name
		// Example: java/sql/ResultSet.getString(*)*:TAINTED
		return className + "." + methodName + "(*)*";
	}
}
