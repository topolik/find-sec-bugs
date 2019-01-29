package com.h3xstream.findsecbugs.kotlin;

import com.h3xstream.findbugs.test.BaseDetectorTest;
import com.h3xstream.findbugs.test.EasyBugReporter;
import com.h3xstream.findsecbugs.FindSecBugsGlobalConfig;
import org.testng.annotations.Test;

import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

public class IdentityFunctionCommandInjectionTest extends BaseDetectorTest {


    @Test
    public void detectCommandInjection() throws Exception {

        //Locate test code
        String[] files = {
                getClassFilePath("com/h3xstream/findsecbugs/command/IdentityFunctionCommandInjection")
        };

        //Run the analysis
        EasyBugReporter reporter = spy(new BaseDetectorTest.SecurityReporter());
        analyze(files, reporter);

        // tained input executed after always true filter
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("COMMAND_INJECTION")
                        .inClass("IdentityFunctionCommandInjection").atLine(25)
                        .withPriority("Medium")
                        .build()
        );

        // tained input executed after always false not filter
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("COMMAND_INJECTION")
                        .inClass("IdentityFunctionCommandInjection").atLine(31)
                        .withPriority("Medium")
                        .build()
        );

        // tained input executed after identity function with run
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("COMMAND_INJECTION")
                        .inClass("IdentityFunctionCommandInjection").atLine(37)
                        .withPriority("Medium")
                        .build()
        );

        // tained input executed after identity function with let
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("COMMAND_INJECTION")
                        .inClass("IdentityFunctionCommandInjection").atLine(43)
                        .withPriority("Medium")
                        .build()
        );

        // tained input executed after identity function with apply
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("COMMAND_INJECTION")
                        .inClass("IdentityFunctionCommandInjection").atLine(47)
                        .withPriority("Medium")
                        .build()
        );

        // tained input executed after drop while always false
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("COMMAND_INJECTION")
                        .inClass("IdentityFunctionCommandInjection").atLine(53)
                        .withPriority("Medium")
                        .build()
        );

        // tained input executed after drop last while always false
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("COMMAND_INJECTION")
                        .inClass("IdentityFunctionCommandInjection").atLine(59)
                        .withPriority("Medium")
                        .build()
        );

        // tained input executed after take while always true
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("COMMAND_INJECTION")
                        .inClass("IdentityFunctionCommandInjection").atLine(65)
                        .withPriority("Medium")
                        .build()
        );

        // tained input executed after take last while always true then reversed
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("COMMAND_INJECTION")
                        .inClass("IdentityFunctionCommandInjection").atLine(71)
                        .withPriority("Medium")
                        .build()
        );

        // tained input executed after trim always false
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("COMMAND_INJECTION")
                        .inClass("IdentityFunctionCommandInjection").atLine(77)
                        .withPriority("Medium")
                        .build()
        );

        // tained input executed after trim end always false
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("COMMAND_INJECTION")
                        .inClass("IdentityFunctionCommandInjection").atLine(83)
                        .withPriority("Medium")
                        .build()
        );

        // tained input executed after trim start always false
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("COMMAND_INJECTION")
                        .inClass("IdentityFunctionCommandInjection").atLine(89)
                        .withPriority("Medium")
                        .build()
        );

        // tained input executed after also does nothing
        verify(reporter).doReportBug(
                bugDefinition()
                        .bugType("COMMAND_INJECTION")
                        .inClass("IdentityFunctionCommandInjection").atLine(95)
                        .withPriority("Medium")
                        .build()
        );
    }
}
