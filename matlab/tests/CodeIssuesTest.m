classdef CodeIssuesTest < matlab.unittest.TestCase
%CODEISSUESTEST The Code Analyzer finds nothing in the package or its tests.

% SPDX-License-Identifier: GPL-3.0-or-later

    methods (Test)
        function thePackageAndItsTestsHaveNoCodeIssue(testCase)
            folder = fileparts(fileparts(mfilename("fullpath")));
            found = codeIssues(folder);
            testCase.verifyEmpty(found.Issues, formattedDisplayText(found.Issues));
        end
    end
end
