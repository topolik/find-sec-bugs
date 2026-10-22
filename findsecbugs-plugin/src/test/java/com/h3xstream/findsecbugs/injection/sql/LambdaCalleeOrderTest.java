package com.h3xstream.findsecbugs.injection.sql;

import com.h3xstream.findbugs.test.BaseDetectorTest;
import com.h3xstream.findbugs.test.EasyBugReporter;
import org.testng.annotations.Test;

import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

public class LambdaCalleeOrderTest extends BaseDetectorTest {

    @Test
    public void resolveSinksOfMethodsCalledFromMethodReference() throws Exception {
        String[] files = {
                getClassFilePath("testcode/sqli/source/LambdaCalleeOrder")
        };

        EasyBugReporter reporter = spy(new SecurityReporter());
        analyze(files, reporter);

        for (int i = 1; i <= 6; i++) {
            verify(reporter, never()).doReportBug(
                    bugDefinition()
                            .bugType("SQL_INJECTION_JDBC")
                            .inClass("LambdaCalleeOrder").inMethod("_sinkSafe" + i)
                            .withPriority("Medium")
                            .build()
            );
            verify(reporter).doReportBug(
                    bugDefinition()
                            .bugType("SQL_INJECTION_JDBC")
                            .inClass("LambdaCalleeOrder").inMethod("_sinkTainted" + i)
                            .withPriority("High")
                            .build()
            );
        }
    }
}
