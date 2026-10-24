package com.h3xstream.findsecbugs.password;

import com.h3xstream.findbugs.test.BaseDetectorTest;
import com.h3xstream.findbugs.test.EasyBugReporter;
import edu.umd.cs.findbugs.AnalysisError;
import org.testng.annotations.Test;

import static org.mockito.Mockito.*;

public class PasswordVariableLoopTest extends BaseDetectorTest {

    @Test
    public void analyzePasswordVariableReassignedInLoop() throws Exception {
        String[] files = {
                getClassFilePath("testcode/password/PasswordVariableLoop")
        };

        EasyBugReporter reporter = spy(new BaseDetectorTest.SecurityReporter());
        analyze(files, reporter);

        verify(reporter, never()).reportAnalysisError(any(AnalysisError.class));
    }
}
