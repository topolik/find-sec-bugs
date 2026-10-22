package com.h3xstream.findsecbugs.taintanalysis;

import com.h3xstream.findbugs.test.BaseDetectorTest;
import com.h3xstream.findbugs.test.EasyBugReporter;
import com.h3xstream.findsecbugs.FindSecBugsGlobalConfig;
import org.testng.annotations.AfterClass;
import org.testng.annotations.Test;

import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

/**
 * Tests a non-capturing lambda (invokedynamic without arguments) with the invokedynamic workaround enabled.
 */
public class NonCapturingLambdaTest extends BaseDetectorTest {

    @Test
    public void analyzeNonCapturingLambda() throws Exception {
        FindSecBugsGlobalConfig.getInstance().setWorkaroundVisitInvokeDynamic(true);

        String[] files = {
                getClassFilePath("testcode/taint/NonCapturingLambda")
        };

        EasyBugReporter reporter = spy(new SecurityReporter());
        analyze(files, reporter);

        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("SQL_INJECTION_JDBC")
                        .inClass("NonCapturingLambda").inMethod("unsafe")
                        .build()
        );
    }

    @AfterClass
    public void resetWorkaround() {
        FindSecBugsGlobalConfig.getInstance().setWorkaroundVisitInvokeDynamic(false);
    }
}
