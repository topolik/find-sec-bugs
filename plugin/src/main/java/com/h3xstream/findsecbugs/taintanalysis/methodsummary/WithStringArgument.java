package com.h3xstream.findsecbugs.taintanalysis.methodsummary;

import com.h3xstream.findsecbugs.taintanalysis.Taint;
import com.h3xstream.findsecbugs.taintanalysis.TaintFrameModelingVisitor;
import com.h3xstream.findsecbugs.taintanalysis.TaintMethodSummary;
import edu.umd.cs.findbugs.ba.DataflowAnalysisException;

import java.util.regex.Pattern;

/**
 * @author Tomas Polesovsky
 */
public class WithStringArgument implements TaintMethodSummaryParser {
	private static final Pattern methodSyntax;
	static {
		// javax/servlet/http/HttpServletRequest.getAttribute("applicationConstant")@org/apache/jsp/edit_jsp.java
		String methodWithStringArgumentsTheArgumentRegex = "\"[^\"]*\"";
		String methodWithStringArgumentsTaintArgumentRegex = "(" + Taint.State.TAINTED.name() + "|" + Taint.State.UNKNOWN.name() +"|" + Taint.State.SAFE.name() + ")";
		String methodWithStringArgumentsSignatureRegex = "\\((" + methodWithStringArgumentsTheArgumentRegex + ",?|" + methodWithStringArgumentsTaintArgumentRegex + ",?)+\\)";
		String methodWithStringArgumentsLocation = "@(.+)";
		String methodWithStringArgumentsRegex = classWithPackageRegex + "\\." + methodRegex + methodWithStringArgumentsSignatureRegex + methodWithStringArgumentsLocation;
		methodSyntax = Pattern.compile(methodWithStringArgumentsRegex);
	}

	@Override
	public boolean accepts(String methodFullName) {
		return methodSyntax.matcher(methodFullName).matches();
	}

	@Override
	public String parse(String className, String methodName, String signature, TaintFrameModelingVisitor taintFrameModelingVisitor) {
		// Matches calls with specific arguments or taint type
		// Example: javax/servlet/http/HttpServletRequest.getAttribute("applicationConstant")@org/apache/jsp/edit_jsp.java:SAFE
		// Example: javax/servlet/http/HttpServletRequest.getAttribute(TAINTED)@org/apache/jsp/edit_jsp.java:TAINTED
		int argumentsNum = taintFrameModelingVisitor.getFrame().getStackDepth() - 1;
		if (argumentsNum > 0) {
			StringBuffer sb = new StringBuffer(argumentsNum);

			for (int i = argumentsNum - 1; i >= 0; i--) {
				try {
					Taint taint = taintFrameModelingVisitor.getFrame().getStackValue(i);
					String value = taint.getConstantValue();
					if (value != null) {
						sb.append('"' + value + '"');
					}
					else {
						sb.append(taint.getState().name());
					}
					if (i > 0) {
						sb.append(',');
					}
				}
				catch (DataflowAnalysisException e) {
					assert false : e.getMessage();
				}
			}

			String methodDefinition = className + "." + methodName + "(" + sb.toString() + ")";

			return methodDefinition + "@" + taintFrameModelingVisitor.getMethodDescriptor().getSlashedClassName();
		}

		return null;
	}
}