classdef RadioReadTest < matlab.unittest.TestCase
%RADIOREADTEST Reading the tables `mooringctl router history --csv` prints.

% SPDX-License-Identifier: GPL-3.0-or-later

    properties
        Folder (1,1) string
    end

    methods (TestMethodSetup)
        function makeFolder(testCase)
            fixture = testCase.applyFixture(matlab.unittest.fixtures.TemporaryFolderFixture);
            testCase.Folder = fixture.Folder;
        end
    end

    methods
        function file = plant(testCase, text)
            file = fullfile(testCase.Folder, "planted.csv");
            writeText(file, text);
        end

        function verifyRefused(testCase, read, text, identifier, part)
            % The planted text is refused with the identifier, and the
            % message holds the part.
            file = testCase.plant(text);
            try
                read(file);
                testCase.verifyFail("The file was read: " + part);
            catch failure
                testCase.verifyEqual(string(failure.identifier), identifier);
                testCase.verifySubstring(failure.message, part);
            end
        end
    end

    methods (Test)
        function theGoldenSamplesAreRead(testCase)
            samples = mooring.readRadioSamples(fixtureFile("radio-samples.csv"));

            testCase.verifyClass(samples, "timetable");
            testCase.verifyEqual(height(samples), 9);
            testCase.verifyEqual(string(samples.Properties.VariableNames), [ ...
                "outcome", "failure", "uptime_secs", "temperature_c", "thermal", "service", ...
                "network_service", "data_service", "band", "ca_secondary_count", ...
                "lte_rsrp_dbm", "lte_rsrq_db", "lte_sinr_db", "lte_rssi_dbm", ...
                "nr_rsrp_dbm", "nr_rsrq_db", "nr_sinr_db", "plmn", "session_secs"]);
            testCase.verifyEqual(string(samples.Properties.DimensionNames{1}), "at");
            testCase.verifyEqual(string(samples.at.TimeZone), "UTC");
            testCase.verifyEqual(posixtime(samples.at), 1791918000 + 60 * (0:8)');
            testCase.verifyEqual(string(samples.at(1), "yyyy-MM-dd HH:mm:ss"), "2026-10-13 19:00:00");

            attached = [1 3 4 6 7 8 9];
            lte = nan(9, 1);
            testCase.verifyEqual(named(samples.outcome), ...
                ["read"; "failed"; "read"; "read"; "read"; "read"; "read"; "read"; "read"]);
            testCase.verifyEqual(named(samples.failure), ["", "unreachable", "", "", "", "", "", "", ""]');
            testCase.verifyEqual(samples.uptime_secs, ...
                [523014; NaN; 523134; 523194; 523254; 523314; 523374; 523434; 40]);
            testCase.verifyEqual(samples.temperature_c, [44; NaN; 44; 44; 44; 44; 44; 44; 44]);
            testCase.verifyEqual(named(samples.thermal), ...
                ["normal"; ""; "normal"; "normal"; "normal"; "normal"; "normal"; "normal"; "normal"]);
            testCase.verifyEqual(named(samples.service), ["attached"; ""; "attached"; "attached"; ...
                "no_service"; "attached"; "attached"; "attached"; "attached"]);
            testCase.verifyEqual(named(samples.network_service), ...
                ["nr5g"; ""; "lte"; "lte"; ""; "lte"; "lte"; "lte"; "lte"]);
            testCase.verifyEqual(named(samples.data_service), ["nr_sub6"; ""; "lte_plus"; "lte_plus"; ...
                ""; "lte_plus"; "lte_plus"; "lte_plus"; "lte_plus"]);
            testCase.verifyEqual(named(samples.band), ...
                ["B3"; ""; "B3"; "B20"; ""; "B20"; "B20"; "B20"; "B20"]);
            lte(attached) = 0;
            testCase.verifyEqual(samples.ca_secondary_count, lte);
            lte(attached) = -100;
            testCase.verifyEqual(samples.lte_rsrp_dbm, lte);
            lte(attached) = -12;
            testCase.verifyEqual(samples.lte_rsrq_db, lte);
            lte(attached) = 2;
            testCase.verifyEqual(samples.lte_sinr_db, lte);
            lte(attached) = -69;
            testCase.verifyEqual(samples.lte_rssi_dbm, lte);
            testCase.verifyEqual(samples.nr_rsrp_dbm, [-90.5; nan(8, 1)]);
            testCase.verifyEqual(samples.nr_rsrq_db, [-10.5; nan(8, 1)]);
            testCase.verifyEqual(samples.nr_sinr_db, [15.5; nan(8, 1)]);
            testCase.verifyEqual(named(samples.plmn), ...
                ["234-30"; ""; "234-30"; "234-30"; ""; "234-30"; "234-30"; "234-20"; "234-20"]);
            testCase.verifyEqual(samples.session_secs, [86400; NaN; 86520; 86580; NaN; 30; 20; 80; 20]);
        end

        function aNameIsCategoricalAndANumberIsADouble(testCase)
            samples = mooring.readRadioSamples(fixtureFile("radio-samples.csv"));
            events = mooring.readRadioEvents(fixtureFile("radio-events.csv"));

            for name = ["outcome", "failure", "thermal", "service", "network_service", ...
                    "data_service", "band", "plmn"]
                testCase.verifyClass(samples.(name), "categorical", name);
            end
            for name = ["uptime_secs", "temperature_c", "ca_secondary_count", "session_secs", ...
                    "lte_rsrp_dbm", "lte_rsrq_db", "lte_sinr_db", "lte_rssi_dbm", ...
                    "nr_rsrp_dbm", "nr_rsrq_db", "nr_sinr_db"]
                testCase.verifyClass(samples.(name), "double", name);
            end
            for name = ["event", "reason", "from", "to"]
                testCase.verifyClass(events.(name), "categorical", name);
            end
            % A value the sample does not hold is undefined, not a category.
            testCase.verifyTrue(isundefined(samples.band(2)));
            testCase.verifyEqual(string(categories(samples.outcome))', ["failed", "read"]);
        end

        function theGoldenEventsAreRead(testCase)
            events = mooring.readRadioEvents(fixtureFile("radio-events.csv"));

            testCase.verifyClass(events, "timetable");
            testCase.verifyEqual(string(events.Properties.VariableNames), ["event", "reason", "from", "to"]);
            testCase.verifyEqual(string(events.Properties.DimensionNames{1}), "at");
            testCase.verifyEqual(string(events.at.TimeZone), "UTC");
            testCase.verifyEqual(posixtime(events.at), 1791918000 + 60 * [1 2 2 2 3 4 5 6 7 8]');
            testCase.verifyEqual(named(events.event), ["poll_failed"; "poll_recovered"; ...
                "network_service_changed"; "data_service_changed"; "band_changed"; "service_lost"; ...
                "service_regained"; "session_restarted"; "plmn_changed"; "router_rebooted"]);
            testCase.verifyEqual(named(events.reason), ["unreachable"; repmat("", 9, 1)]);
            testCase.verifyEqual(named(events.from), ...
                [""; ""; "nr5g"; "nr_sub6"; "B3"; ""; ""; ""; "234-30"; ""]);
            testCase.verifyEqual(named(events.to), ...
                [""; ""; "lte"; "lte_plus"; "B20"; ""; ""; ""; "234-20"; ""]);
        end

        function aTableWithoutRowsIsItsVariablesWithoutRows(testCase)
            for name = ["samples", "events"]
                golden = splitlines(string(fileread(fixtureFile("radio-" + name + ".csv"))));
                file = testCase.plant(golden(1) + newline);
                if name == "samples"
                    read = mooring.readRadioSamples(file);
                    whole = mooring.readRadioSamples(fixtureFile("radio-samples.csv"));
                else
                    read = mooring.readRadioEvents(file);
                    whole = mooring.readRadioEvents(fixtureFile("radio-events.csv"));
                end
                testCase.verifyClass(read, "timetable", name);
                testCase.verifyEqual(height(read), 0, name);
                testCase.verifyEqual(read.Properties.VariableNames, whole.Properties.VariableNames, name);
                testCase.verifyEqual(string(read.at.TimeZone), "UTC", name);
                testCase.verifyEqual(varfun(@class, read, "OutputFormat", "cell"), ...
                    varfun(@class, whole, "OutputFormat", "cell"), name);
            end
        end

        function aTableOfOneRowIsRead(testCase)
            golden = splitlines(string(fileread(fixtureFile("radio-samples.csv"))));
            one = mooring.readRadioSamples(testCase.plant(golden(1) + newline + golden(2) + newline));
            testCase.verifyEqual(height(one), 1);
            testCase.verifyEqual(posixtime(one.at), 1791918000);
            testCase.verifyEqual(named(one.band), "B3");
            testCase.verifyEqual(one.lte_rsrp_dbm, -100);
            testCase.verifyEqual(one.nr_sinr_db, 15.5);
            testCase.verifyEqual(named(one.plmn), "234-30");
            testCase.verifyEqual(one.session_secs, 86400);

            golden = splitlines(string(fileread(fixtureFile("radio-events.csv"))));
            one = mooring.readRadioEvents(testCase.plant(golden(1) + newline + golden(6) + newline));
            testCase.verifyEqual(height(one), 1);
            testCase.verifyEqual(named(one.event), "band_changed");
            testCase.verifyEqual(named(one.from), "B3");
            testCase.verifyEqual(named(one.to), "B20");
        end

        function lineEndsOfCrLfAreLineEnds(testCase)
            golden = string(fileread(fixtureFile("radio-samples.csv")));
            carried = replace(golden, newline, char(13) + string(newline));
            testCase.assertEqual(count(carried, char(13)), 10);
            testCase.verifyTrue(isequaln(mooring.readRadioSamples(testCase.plant(carried)), ...
                mooring.readRadioSamples(fixtureFile("radio-samples.csv"))));
            % A carriage return that ends no line is no part of a row.
            testCase.verifyRefused(@mooring.readRadioSamples, ...
                replace(golden, "523134,44", "523134" + char(13) + ",44"), ...
                "mooring:radio:BadRow", "Line 4 ");
        end

        function anotherFirstLineIsRefused(testCase)
            samples = string(fileread(fixtureFile("radio-samples.csv")));
            events = string(fileread(fixtureFile("radio-events.csv")));
            unknown = "mooring:radio:UnknownHeader";

            testCase.verifyRefused(@mooring.readRadioSamples, events, unknown, "at_unix,at_utc,event");
            testCase.verifyRefused(@mooring.readRadioEvents, samples, unknown, "at_unix,at_utc,outcome");
            % A column under another name, a column more, and no header.
            testCase.verifyRefused(@mooring.readRadioSamples, ...
                replace(samples, "lte_rsrp_dbm", "lte_rsrp"), unknown, "lte_rsrp,");
            testCase.verifyRefused(@mooring.readRadioSamples, ...
                replace(samples, "plmn,session_secs", "plmn,session_secs,cell"), unknown, ...
                "plmn,session_secs,cell" + newline);
            testCase.verifyRefused(@mooring.readRadioSamples, ...
                extractAfter(samples, newline), unknown, "1791918000,");
            testCase.verifyRefused(@mooring.readRadioEvents, ...
                replace(events, "from,to", "to,from"), unknown, "to,from");
            testCase.verifyRefused(@mooring.readRadioSamples, newline, unknown, "found:");
        end

        function aLongFirstLineIsShownAsFarAsAHeaderWithColumnsAddedReaches(testCase)
            % The header's own length and 80 characters more: 307 for the
            % samples, whose header has 227, and 115 for the events.
            found = @(count) "found:    " + string(repmat('x', 1, count));
            cases = { ...
                @mooring.readRadioSamples, 5000, found(307) + "..." + newline; ...
                @mooring.readRadioSamples, 308, found(307) + "..." + newline; ...
                @mooring.readRadioSamples, 307, found(307) + newline; ...
                @mooring.readRadioEvents, 5000, found(115) + "..." + newline; ...
                @mooring.readRadioEvents, 115, found(115) + newline};
            for index = 1:size(cases, 1)
                read = cases{index, 1};
                file = testCase.plant(string(repmat('x', 1, cases{index, 2})) + newline);
                try
                    read(file);
                    testCase.verifyFail("The file was read.");
                catch failure
                    testCase.verifyEqual(string(failure.identifier), "mooring:radio:UnknownHeader");
                    testCase.verifySubstring(failure.message, cases{index, 3});
                    testCase.verifyLessThan(strlength(failure.message), 1000);
                end
            end
        end

        function aFileCutShortIsRefused(testCase)
            samples = string(fileread(fixtureFile("radio-samples.csv")));
            events = string(fileread(fixtureFile("radio-events.csv")));
            cut = "mooring:radio:Incomplete";

            testCase.verifyRefused(@mooring.readRadioSamples, strip(samples, "right", newline), cut, "line end");
            testCase.verifyRefused(@mooring.readRadioEvents, strip(events, "right", newline), cut, "line end");
            testCase.verifyRefused(@mooring.readRadioSamples, extractBefore(samples, 400), cut, "line end");
            testCase.verifyRefused(@mooring.readRadioSamples, "", cut, "line end");
        end

        function aLineThatIsNoRowIsRefusedAndNumbered(testCase)
            samples = string(fileread(fixtureFile("radio-samples.csv")));
            events = string(fileread(fixtureFile("radio-events.csv")));
            bad = "mooring:radio:BadRow";
            % The fourth line is the read at 19:02, the third the failed poll.
            cases = [ ...
                "read,,523134", "maybe,,523134", "Line 4 "; ...
                "read,,523134", "READ,,523134", "Line 4 "; ...
                "read,,523134", "read,523134", "Line 4 "; ...
                "read,,523134", "read,,,523134", "Line 4 "; ...
                "523134,44,normal", "523134,44.5,normal", "Line 4 "; ...
                "523134,44,normal", "523134,44,Normal", "Line 4 "; ...
                "86520", "86520.0", "Line 4 "; ...
                "86520", "-86520", "Line 4 "; ...
                "86520", "86520,", "Line 4 "; ...
                "B3,0,-100.0,-12.0,2.0,-69.0,,,,234-30,86520", ...
                "B3,0,-100.00,-12.0,2.0,-69.0,,,,234-30,86520", "Line 4 "; ...
                "B3,0,-100.0,-12.0,2.0,-69.0,,,,234-30,86520", ...
                "B3,0,-100,-12.0,2.0,-69.0,,,,234-30,86520", "Line 4 "; ...
                "B3,0,-100.0,-12.0,2.0,-69.0,,,,234-30,86520", ...
                "b3,0,-100.0,-12.0,2.0,-69.0,,,,234-30,86520", "Line 4 "; ...
                "B3,0,-100.0,-12.0,2.0,-69.0,,,,234-30,86520", ...
                "B3,0,-100.0,-12.0,2.0,-69.0,,,,23430,86520", "Line 4 "; ...
                "B3,0,-100.0,-12.0,2.0,-69.0,,,,234-30,86520", ...
                "B3,0,NaN,-12.0,2.0,-69.0,,,,234-30,86520", "Line 4 "; ...
                "1791918060,2026-10-13T19:01:00Z", "1791918060,2026-10-13 19:01:00Z", "Line 3 "; ...
                "1791918060,2026-10-13T19:01:00Z", "1791918060,2026-10-13T19:01:00", "Line 3 "; ...
                "1791918060,2026-10-13T19:01:00Z", "1791918060.0,2026-10-13T19:01:00Z", "Line 3 "; ...
                "1791918060,2026-10-13T19:01:00Z", "1791918060000,2026-10-13T19:01:00Z", "Line 3 "; ...
                "1791918060,2026-10-13T19:01:00Z", newline + "1791918060,2026-10-13T19:01:00Z", "Line 3 "; ...
                "failed,unreachable", "failed,un reachable", "Line 3 "];
            for index = 1:size(cases, 1)
                testCase.verifyRefused(@mooring.readRadioSamples, ...
                    replace(samples, cases(index, 1), cases(index, 2)), bad, cases(index, 3));
            end
            testCase.verifyRefused(@mooring.readRadioEvents, ...
                replace(events, "band_changed,,B3,B20", "band_changed,,B3,B20,"), bad, "Line 6 ");
            testCase.verifyRefused(@mooring.readRadioEvents, ...
                replace(events, "band_changed,,B3,B20", "band changed,,B3,B20"), bad, "Line 6 ");
            testCase.verifyRefused(@mooring.readRadioEvents, ...
                replace(events, "band_changed,,B3,B20", ",,B3,B20"), bad, "Line 6 ");
            % A table of the right header whose only line is no row.
            testCase.verifyRefused(@mooring.readRadioEvents, ...
                extractBefore(events, newline) + newline + "nothing" + newline, bad, "Line 2 ");
        end

        function aRowWhoseTwoTimesDifferIsRefused(testCase)
            samples = string(fileread(fixtureFile("radio-samples.csv")));
            events = string(fileread(fixtureFile("radio-events.csv")));
            differ = "mooring:radio:TimeMismatch";

            testCase.verifyRefused(@mooring.readRadioSamples, ...
                replace(samples, "2026-10-13T19:01:00Z", "2026-10-13T19:01:01Z"), differ, "Line 3 ");
            testCase.verifyRefused(@mooring.readRadioSamples, ...
                replace(samples, "1791918480,", "1791918481,"), differ, "Line 10 ");
            % A stamp that is no time at all, and one of another zone's hour.
            testCase.verifyRefused(@mooring.readRadioSamples, ...
                replace(samples, "2026-10-13T19:01:00Z", "2026-13-45T25:61:61Z"), differ, "2026-13-45T25:61:61Z");
            testCase.verifyRefused(@mooring.readRadioSamples, ...
                replace(samples, "2026-10-13T19:01:00Z", "2026-10-13T20:01:00Z"), differ, "1791918060 seconds");
            testCase.verifyRefused(@mooring.readRadioEvents, ...
                replace(events, "1791918180,2026-10-13T19:03:00Z", "1791918180,2026-10-13T19:04:00Z"), ...
                differ, "Line 6 ");
        end

        function aFileThatIsNotThereIsRefused(testCase)
            absent = fullfile(testCase.Folder, "absent.csv");
            testCase.verifyError(@() mooring.readRadioSamples(absent), "mooring:radio:NoFile");
            testCase.verifyError(@() mooring.readRadioEvents(absent), "mooring:radio:NoFile");
            testCase.verifyError(@() mooring.readRadioSamples(testCase.Folder), "mooring:radio:NoFile");
        end

        function theQuantilesAreInterpolatedBetweenTheValuesInOrder(testCase)
            quantiles = @mooring.internal.quantiles;
            testCase.verifyEqual(quantiles([3 1 2], 0.5), 2);
            testCase.verifyEqual(quantiles([4; 1; 3; 2], [0 0.5 1]), [1 2.5 4]);
            testCase.verifyEqual(quantiles([10 20 30 40 50], [0.1; 0.9]), [14; 46], "AbsTol", 1e-12);
            testCase.verifyEqual(quantiles([NaN 5 NaN 7], [0.25 0.75]), [5.5 6.5]);
            testCase.verifyEqual(quantiles(7, [0 0.3 1]), [7 7 7]);
            testCase.verifyEqual(quantiles([NaN NaN], [0.1 0.9]), [NaN NaN]);
            testCase.verifyEqual(quantiles(zeros(0, 1), 0.5), NaN);
            testCase.verifyError(@() quantiles([1 2], 1.5), "MATLAB:validators:mustBeLessThanOrEqual");
            testCase.verifyError(@() quantiles([1 2], -0.5), "MATLAB:validators:mustBeNonnegative");
        end
    end
end

function text = named(column)
% A categorical column's names, with "" for an undefined value.
    text = string(column);
    text(ismissing(text)) = "";
end
