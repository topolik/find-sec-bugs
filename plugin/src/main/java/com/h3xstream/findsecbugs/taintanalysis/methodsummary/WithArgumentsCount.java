package com.h3xstream.findsecbugs.taintanalysis.methodsummary;

import com.h3xstream.findsecbugs.taintanalysis.TaintFrameModelingVisitor;

import java.util.regex.Pattern;

/**
 * @author Tomas Polesovsky
 */
public class WithArgumentsCount implements TaintMethodSummaryParser {
	private static final Pattern methodSyntax;
	static {
		// java/lang/String.valueOf(1)Ljava/lang/String;
		String methodWithArgumentCountSignatureRegex =  "\\([0-9]+\\)";
		String methodWithArgumentCountRegex = classWithPackageRegex + "\\." + methodRegex + methodWithArgumentCountSignatureRegex  + returnRegex;
		methodSyntax = Pattern.compile(methodWithArgumentCountRegex);
	}

	@Override
	public boolean accepts(String methodFullName) {
		return methodSyntax.matcher(methodFullName).matches();
	}

	@Override
	public String parse(String className, String methodName, String signature, TaintFrameModelingVisitor taintFrameModelingVisitor) {
		String returnType = getReturnType(signature);

		// Matches all methods with same number of arguments, regardless of the argument type
		// Example: java/lang/String.valueOf(1)Ljava/lang/String;
		int argumentsNum = taintFrameModelingVisitor.getFrame().getStackDepth() - 1;
		return className + "." + methodName + "(" + argumentsNum +")"+returnType;
	}

	private static String getReturnType(String signature) {
		assert signature != null && signature.contains(")");
		return signature.substring(signature.indexOf(')') + 1);
	}

}