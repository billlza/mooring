classdef RadioHourlyTest < matlab.unittest.TestCase
%RADIOHOURLYTEST Each hour's polls and median readings.

% SPDX-License-Identifier: GPL-3.0-or-later

    properties (Constant)
        % 2026-10-13 19:00:00 UTC.
        Base = 1791918000
        Names = ["polls", "failed", "no_service", "attached", "nr5g_share", ...
            "ca_secondary_mean", "temperature_c", "lte_rsrp_dbm", "lte_rsrq_db", ...
            "lte_sinr_db", "lte_rssi_dbm", "nr_rsrp_dbm", "nr_rsrq_db", "nr_sinr_db"]
    end

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
        function samples = fourHours(testCase, order)
            % Five polls from 19:00, none from 20:00, a failed one after
            % 21:00 and two reads from 22:00, in the given order.
            at = testCase.Base + [0; 60; 120; 180; 240; 7230; 10800; 10860];
            kind = ["attached"; "attached"; "attached"; "failed"; "no_service"; ...
                "failed"; "attached"; "attached"];
            readings = [ ...
                -100, -12, 2, -69, -90.5, -10.5, 15.5; ...
                -101, -13, 4, -70, NaN, NaN, NaN; ...
                -99, -11, 9, -68, NaN, NaN, NaN; ...
                nan(3, 7); ...
                -95, -10, 12, -60, NaN, NaN, NaN; ...
                -97, -12, 14, -62, NaN, NaN, NaN];
            network = ["nr5g"; "lte"; "lte"; "lte"; "lte"; "lte"; "lte"; "lte"];
            carriers = [2; 1; 0; 0; 0; 0; 0; 0];
            samples = radioPolls(testCase.Folder, at(order), kind(order), ...
                readings(order, :), network(order), carriers(order));
        end
    end

    methods (Test)
        function anHourHoldsItsPollsAndTheMediansOfItsReadings(testCase)
            hourly = mooring.radioHourly(testCase.fourHours(1:8));

            testCase.verifyClass(hourly, "timetable");
            testCase.verifyEqual(string(hourly.Properties.VariableNames), testCase.Names);
            testCase.verifyEqual(string(hourly.Properties.DimensionNames{1}), "hour");
            testCase.verifyEqual(string(hourly.hour.TimeZone), "UTC");
            % Every hour from the first poll's to the last poll's, the one
            % without a poll among them.
            testCase.verifyEqual(posixtime(hourly.hour), testCase.Base + 3600 * (0:3)');
            testCase.verifyEqual(hourly.polls, [5; 0; 1; 2]);
            testCase.verifyEqual(hourly.failed, [1; 0; 1; 0]);
            testCase.verifyEqual(hourly.no_service, [1; 0; 0; 0]);
            testCase.verifyEqual(hourly.attached, [3; 0; 0; 2]);
            testCase.verifyEqual(hourly.nr5g_share, [1 / 3; NaN; NaN; 0], "AbsTol", 1e-12);
            testCase.verifyEqual(hourly.ca_secondary_mean, [1; NaN; NaN; 0]);
            % The temperature is of the polls that read, without service too.
            testCase.verifyEqual(hourly.temperature_c, [44; NaN; NaN; 44]);
            % Three readings' median is the middle one, two readings' the
            % mean of the two.
            testCase.verifyEqual(hourly.lte_rsrp_dbm, [-100; NaN; NaN; -96]);
            testCase.verifyEqual(hourly.lte_rsrq_db, [-12; NaN; NaN; -11]);
            testCase.verifyEqual(hourly.lte_sinr_db, [4; NaN; NaN; 13]);
            testCase.verifyEqual(hourly.lte_rssi_dbm, [-69; NaN; NaN; -61]);
            % A reading one poll of the hour reported is that poll's.
            testCase.verifyEqual(hourly.nr_rsrp_dbm, [-90.5; NaN; NaN; NaN]);
            testCase.verifyEqual(hourly.nr_rsrq_db, [-10.5; NaN; NaN; NaN]);
            testCase.verifyEqual(hourly.nr_sinr_db, [15.5; NaN; NaN; NaN]);
        end

        function theOrderOfThePollsDoesNotCount(testCase)
            inOrder = mooring.radioHourly(testCase.fourHours(1:8));
            shuffled = mooring.radioHourly(testCase.fourHours([8 3 1 6 2 7 5 4]));
            testCase.verifyTrue(isequaln(shuffled, inOrder));
        end

        function anHourBeginsOnItsFirstSecond(testCase)
            at = testCase.Base + [3599; 3600; 7199];
            samples = radioPolls(testCase.Folder, at, repmat("attached", 3, 1), ...
                [-100, -12, 1, -69, NaN, NaN, NaN; -100, -12, 2, -69, NaN, NaN, NaN; ...
                -100, -12, 4, -69, NaN, NaN, NaN], repmat("lte", 3, 1), zeros(3, 1));
            hourly = mooring.radioHourly(samples);
            testCase.verifyEqual(posixtime(hourly.hour), testCase.Base + [0; 3600]);
            testCase.verifyEqual(hourly.polls, [1; 2]);
            testCase.verifyEqual(hourly.lte_sinr_db, [1; 3]);
        end

        function polledWithoutEverAttachingIsCountsWithoutReadings(testCase)
            at = testCase.Base + [0; 60; 3600];
            samples = radioPolls(testCase.Folder, at, ["failed"; "no_service"; "failed"], ...
                nan(3, 7), repmat("lte", 3, 1), zeros(3, 1));
            hourly = mooring.radioHourly(samples);
            testCase.verifyEqual(hourly.polls, [2; 1]);
            testCase.verifyEqual(hourly.failed, [1; 1]);
            testCase.verifyEqual(hourly.no_service, [1; 0]);
            testCase.verifyEqual(hourly.attached, [0; 0]);
            testCase.verifyEqual(hourly.temperature_c, [44; NaN]);
            for name = ["nr5g_share", "ca_secondary_mean", testCase.Names(8:end)]
                testCase.verifyEqual(hourly.(name), [NaN; NaN], name);
            end
        end

        function noSamplesAreNoHours(testCase)
            hourly = mooring.radioHourly(noRadioSamples(testCase.Folder));
            testCase.verifyClass(hourly, "timetable");
            testCase.verifyEqual(height(hourly), 0);
            testCase.verifyEqual(string(hourly.Properties.VariableNames), testCase.Names);
            testCase.verifyEqual(string(hourly.hour.TimeZone), "UTC");
        end

        function aTimetableThatIsNotOfSamplesIsRefused(testCase)
            other = timetable(datetime(2026, 10, 13, "TimeZone", "UTC"), 1);
            events = mooring.readRadioEvents(fixtureFile("radio-events.csv"));
            testCase.verifyError(@() mooring.radioHourly(other), "mooring:radio:NotSamples");
            testCase.verifyError(@() mooring.radioHourly(events), "mooring:radio:NotSamples");
            testCase.verifyError(@() mooring.radioDegradation(events), "mooring:radio:NotSamples");
            testCase.verifyError(@() mooring.radioForecast(events), "mooring:radio:NotSamples");
            testCase.verifyError(@() mooring.plotRadio(events), "mooring:radio:NotSamples");
            % The message names what is not there.
            samples = mooring.readRadioSamples(fixtureFile("radio-samples.csv"));
            try
                mooring.radioHourly(removevars(samples, ["band", "plmn"]));
                testCase.verifyFail("The timetable was taken.");
            catch failure
                testCase.verifyEqual(string(failure.identifier), "mooring:radio:NotSamples");
                testCase.verifySubstring(failure.message, "band, plmn");
            end
        end
    end
end
