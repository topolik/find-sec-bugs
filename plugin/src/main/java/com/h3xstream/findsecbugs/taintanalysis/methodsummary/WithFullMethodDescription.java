package com.h3xstream.findsecbugs.taintanalysis.methodsummary;

import com.h3xstream.findsecbugs.taintanalysis.TaintFrameModelingVisitor;

import java.util.regex.Pattern;

/**
 * @author Tomas Polesovsky
 */
public class WithFullMethodDescription implements TaintMethodSummaryParser {
	private static final Pattern methodSyntax;
	static {
		// java/lang/String.valueOf(Z)Ljava/lang/String;
		String fullMethodNameRegex = classWithPackageRegex + "\\." + methodRegex + signatureRegex;
		methodSyntax = Pattern.compile(fullMethodNameRegex);
	}

	@Override
	public boolean accepts(String methodFullName) {
		return methodSyntax.matcher(methodFullName).matches();
	}

	@Override
	public String parse(String className, String methodName, String signature, TaintFrameModelingVisitor taintFrameModelingVisitor) {
		// Classic match - matches class definition with full signature
		// Example: java/lang/String.valueOf(Z)Ljava/lang/String;:SAFE
		String methodId = "." + methodName + signature;
		return className.concat(methodId);
	}
}
