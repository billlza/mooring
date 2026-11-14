classdef RadioHistoryTest < matlab.unittest.TestCase
%RADIOHISTORYTEST Reading the history through mooringctl, with a stand-in.
%   The stand-in is a shell script that records its arguments and prints
%   the golden tables, so these tests run where a shell does.

% SPDX-License-Identifier: GPL-3.0-or-later

    properties
        Folder (1,1) string
    end

    methods (TestMethodSetup)
        function makeFolder(testCase)
            testCase.assumeTrue(isunix, "The stand-in for mooringctl is a shell script.");
            fixture = testCase.applyFixture(matlab.unittest.fixtures.TemporaryFolderFixture);
            % A folder whose name the shell must be given quoted, as
            % "Application Support" must be.
            testCase.Folder = fullfile(fixture.Folder, "the operator's folder");
            mkdir(testCase.Folder);
        end
    end

    methods
        function program = standIn(testCase, lines)
            % A program named mooringctl that runs the lines.
            program = fullfile(testCase.Folder, "mooringctl");
            writeText(program, join(["#!/bin/sh"; lines], newline) + newline);
            [status, said] = system("chmod +x " + shellWord(program));
            testCase.assertEqual(status, 0, "chmod said: " + said);
        end

        function program = printsTheGoldenTables(testCase)
            program = testCase.standIn([ ...
                "printf '%s\n' ""$*"" >> ""$(dirname ""$0"")/calls"""; ...
                "case ""$*"" in"; ...
                "  *'--csv samples') cat '" + fixtureFile("radio-samples.csv") + "' ;;"; ...
                "  *'--csv events') cat '" + fixtureFile("radio-events.csv") + "' ;;"; ...
                "  *) echo ""not a table: $*"" >&2; exit 64 ;;"; ...
                "esac"]);
        end

        function lines = calls(testCase)
            % The arguments of each run of the stand-in, one line per run.
            lines = splitlines(strip(string(fileread(fullfile(testCase.Folder, "calls"))), "right", newline));
        end
    end

    methods (Test)
        function theTwoTablesAreAskedForAndRead(testCase)
            [samples, events] = mooring.radioHistory(Mooringctl=testCase.printsTheGoldenTables());

            testCase.verifyTrue(isequaln(samples, mooring.readRadioSamples(fixtureFile("radio-samples.csv"))));
            testCase.verifyTrue(isequaln(events, mooring.readRadioEvents(fixtureFile("radio-events.csv"))));
            testCase.verifyEqual(height(samples), 9);
            testCase.verifyEqual(height(events), 10);
            % Without a range the command's own default applies.
            testCase.verifyEqual(testCase.calls(), ...
                ["router history --csv samples"; "router history --csv events"]);
        end

        function theRangeIsHandedToTheCommand(testCase)
            program = testCase.printsTheGoldenTables();

            mooring.radioHistory(Mooringctl=program, Since="2026-10-12", Until="2026-10-13");
            mooring.radioHistory(Mooringctl=program, Since="2026-07-16");
            mooring.radioHistory(Mooringctl=program, Until="2026-10-13");
            testCase.verifyEqual(testCase.calls(), [ ...
                "router history --since 2026-10-12 --until 2026-10-13 --csv samples"; ...
                "router history --since 2026-10-12 --until 2026-10-13 --csv events"; ...
                "router history --since 2026-07-16 --csv samples"; ...
                "router history --since 2026-07-16 --csv events"; ...
                "router history --until 2026-10-13 --csv samples"; ...
                "router history --until 2026-10-13 --csv events"]);
        end

        function daysCountBackFromTodayInUtc(testCase)
            program = testCase.printsTheGoldenTables();
            % Midnight may pass between the two readings of the clock.
            day = @(back) string(datetime("now", "TimeZone", "UTC") - days(back), "uuuu-MM-dd");
            before = [day(0), day(6), day(89)];
            mooring.radioHistory(Mooringctl=program, Days=1);
            mooring.radioHistory(Mooringctl=program, Days=7);
            mooring.radioHistory(Mooringctl=program, Days=90);
            after = [day(0), day(6), day(89)];

            asked = testCase.calls();
            testCase.verifyTrue(ismember(asked(1), "router history --since " + [before(1), after(1)] + " --csv samples"), asked(1));
            testCase.verifyTrue(ismember(asked(3), "router history --since " + [before(2), after(2)] + " --csv samples"), asked(3));
            testCase.verifyTrue(ismember(asked(5), "router history --since " + [before(3), after(3)] + " --csv samples"), asked(5));
            testCase.verifyNumElements(asked, 6);

            both = "mooring:radio:DaysAndRange";
            testCase.verifyError(@() mooring.radioHistory(Mooringctl=program, Days=7, Since="2026-10-12"), both);
            testCase.verifyError(@() mooring.radioHistory(Mooringctl=program, Days=7, Until="2026-10-13"), both);
            testCase.verifyError(@() mooring.radioHistory(Mooringctl=program, Days=0), ...
                "MATLAB:validators:mustBePositive");
            testCase.verifyError(@() mooring.radioHistory(Mooringctl=program, Days=91), ...
                "MATLAB:validators:mustBeLessThanOrEqual");
            testCase.verifyError(@() mooring.radioHistory(Mooringctl=program, Days=1.5), ...
                "MATLAB:validators:mustBeInteger");
            % None of the refused calls ran the command.
            testCase.verifyNumElements(testCase.calls(), 6);
        end

        function aDayInAnotherFormNeverReachesTheCommandLine(testCase)
            program = testCase.printsTheGoldenTables();
            bad = "mooring:radio:BadDay";
            for day = ["2026-1-3", "13-10-2026", "20261013", "2026-10-13 ", " 2026-10-13", ...
                    "2026-10-13; touch x", "$(touch x)", "2026-10-13" + newline, "today"]
                testCase.verifyError(@() mooring.radioHistory(Mooringctl=program, Since=day), bad, day);
                testCase.verifyError(@() mooring.radioHistory(Mooringctl=program, Until=day), bad, day);
            end
            testCase.verifyFalse(isfile(fullfile(testCase.Folder, "calls")));
        end

        function aCommandThatFailsIsAnErrorWithWhatItSaid(testCase)
            program = testCase.standIn([ ...
                "echo ""mooringctl: the radio history's files failed"" >&2"; ...
                "exit 2"]);
            try
                mooring.radioHistory(Mooringctl=program);
                testCase.verifyFail("A history was returned.");
            catch failure
                testCase.verifyEqual(string(failure.identifier), "mooring:radio:CommandFailed");
                testCase.verifySubstring(failure.message, "status 2");
                testCase.verifySubstring(failure.message, "mooringctl: the radio history's files failed");
            end
        end

        function aTableCutShortIsRefusedAsFromAFile(testCase)
            % The samples' table without its last line end.
            program = testCase.standIn( ...
                "printf '%s' ""$(cat '" + fixtureFile("radio-samples.csv") + "')""");
            testCase.verifyError(@() mooring.radioHistory(Mooringctl=program), "mooring:radio:Incomplete");
            % A table that is not the one asked for.
            program = testCase.standIn("cat '" + fixtureFile("radio-events.csv") + "'");
            testCase.verifyError(@() mooring.radioHistory(Mooringctl=program), "mooring:radio:UnknownHeader");
        end

        function aProgramThatIsNotThereIsSaidSo(testCase)
            absent = fullfile(testCase.Folder, "absent", "mooringctl");
            try
                mooring.radioHistory(Mooringctl=absent);
                testCase.verifyFail("A history was returned.");
            catch failure
                testCase.verifyEqual(string(failure.identifier), "mooring:radio:NoMooringctl");
                testCase.verifySubstring(failure.message, absent);
                testCase.verifySubstring(failure.message, "mooring.readRadioSamples");
            end
        end

        function withoutAProgramNamedItIsTheInstalledAppsUnderTheHomeFolder(testCase)
            % HOME points at a folder that holds no app while this runs, so
            % that the test neither finds nor runs the Mac's own mooringctl.
            homeFolder = fullfile(testCase.Folder, "home");
            testCase.applyFixture(matlab.unittest.fixtures.EnvironmentVariableFixture("HOME", homeFolder));
            try
                mooring.radioHistory();
                testCase.verifyFail("A history was returned.");
            catch failure
                testCase.verifyEqual(string(failure.identifier), "mooring:radio:NoMooringctl");
                testCase.verifySubstring(failure.message, ...
                    fullfile(homeFolder, "Applications", "Mooring.app", "Contents", "MacOS", "mooringctl"));
            end
        end
    end
end

function word = shellWord(text)
% One word for the shell, whatever the text holds.
    word = "'" + replace(text, "'", "'\''") + "'";
end
