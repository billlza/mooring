classdef RadioDegradationTest < matlab.unittest.TestCase
%RADIODEGRADATIONTEST The last day's link against the week before it.

% SPDX-License-Identifier: GPL-3.0-or-later

    properties (Constant)
        % The last poll: 2026-10-13 23:50:00 UTC.
        Last = 1791935400
        Indicators = ["lte_rsrp_dbm"; "lte_rsrq_db"; "lte_sinr_db"; "lte_rssi_dbm"; ...
            "nr_rsrp_dbm"; "nr_rsrq_db"; "nr_sinr_db"; "poll_failed_share"; ...
            "no_service_share"; "nr5g_share"; "ca_secondary_mean"]
        % What every poll reads unless a test says otherwise: LTE only.
        Steady = [-95, -10, 10, -60, NaN, NaN, NaN]
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
        function [at, recent] = eightDays(testCase)
            % A poll every ten minutes for eight days: 1152 polls, the
            % last 144 of them in the last 24 hours and 1008 before.
            at = (testCase.Last - 600 * 1151:600:testCase.Last)';
            recent = at > testCase.Last - 86400;
        end

        function samples = attachedOnLte(testCase, at, readings)
            count = numel(at);
            samples = radioPolls(testCase.Folder, at, repmat("attached", count, 1), ...
                readings, repmat("lte", count, 1), ones(count, 1));
        end

        function samples = lowerInTheLastDay(testCase)
            % RSRP 2.9 dB lower, RSRQ 2 dB lower and SINR 3 dB lower in
            % the last 24 hours than in the week before.
            [at, recent] = testCase.eightDays();
            readings = repmat(testCase.Steady, numel(at), 1);
            readings(recent, 1) = -97.9;
            readings(recent, 2) = -12;
            readings(recent, 3) = 7;
            samples = testCase.attachedOnLte(at, readings);
        end
    end

    methods (Test)
        function aMedianLowerByItsThresholdIsDegraded(testCase)
            [indicators, verdict] = mooring.radioDegradation(testCase.lowerInTheLastDay());

            testCase.verifyClass(indicators, "table");
            testCase.verifyEqual(string(indicators.Properties.VariableNames), ["indicator", "recent", ...
                "baseline", "change", "threshold", "worse_when", "recent_count", "baseline_count", "state"]);
            testCase.verifyEqual(indicators.indicator, testCase.Indicators);
            testCase.verifyEqual(indicators.recent, [-97.9; -12; 7; -60; NaN; NaN; NaN; 0; 0; 0; 1]);
            testCase.verifyEqual(indicators.baseline, [-95; -10; 10; -60; NaN; NaN; NaN; 0; 0; 0; 1]);
            testCase.verifyEqual(indicators.change, [-2.9; -2; -3; 0; NaN; NaN; NaN; 0; 0; 0; 0], ...
                "AbsTol", 1e-9);
            testCase.verifyEqual(indicators.threshold, [3; 2; 3; 3; 3; 2; 3; 0.05; 0.05; 0.2; 0.5]);
            testCase.verifyEqual(indicators.worse_when, ...
                [repmat("lower", 7, 1); "higher"; "higher"; "lower"; "lower"]);
            testCase.verifyEqual(indicators.recent_count, [144; 144; 144; 144; 0; 0; 0; 144; 144; 144; 144]);
            testCase.verifyEqual(indicators.baseline_count, ...
                [1008; 1008; 1008; 1008; 0; 0; 0; 1008; 1008; 1008; 1008]);
            % 2.9 dB is under RSRP's 3; 2 dB is RSRQ's 2 and 3 dB SINR's 3.
            % The NR readings no poll reported have nothing to compare.
            testCase.verifyEqual(indicators.state, ["ok"; "degraded"; "degraded"; "ok"; ...
                "insufficient_data"; "insufficient_data"; "insufficient_data"; "ok"; "ok"; "ok"; "ok"]);
            testCase.verifyEqual(verdict, "degraded");
        end

        function aLinkAsItWasIsOk(testCase)
            at = testCase.eightDays();
            samples = testCase.attachedOnLte(at, repmat(testCase.Steady, numel(at), 1));
            [indicators, verdict] = mooring.radioDegradation(samples);
            testCase.verifyEqual(indicators.change, [0; 0; 0; 0; NaN; NaN; NaN; 0; 0; 0; 0]);
            testCase.verifyEqual(indicators.state, ["ok"; "ok"; "ok"; "ok"; ...
                "insufficient_data"; "insufficient_data"; "insufficient_data"; "ok"; "ok"; "ok"; "ok"]);
            testCase.verifyEqual(verdict, "ok");
        end

        function aBetterLinkIsOk(testCase)
            [at, recent] = testCase.eightDays();
            readings = repmat(testCase.Steady, numel(at), 1);
            readings(recent, 1:4) = readings(recent, 1:4) + 10;
            [indicators, verdict] = mooring.radioDegradation(testCase.attachedOnLte(at, readings));
            testCase.verifyEqual(indicators.change(1:4), [10; 10; 10; 10]);
            testCase.verifyEqual(indicators.state(1:4), ["ok"; "ok"; "ok"; "ok"]);
            testCase.verifyEqual(verdict, "ok");
        end

        function failedPollsLostServiceLess5gAndFewerCarriersAreDegraded(testCase)
            [at, recent] = testCase.eightDays();
            count = numel(at);
            kind = repmat("attached", count, 1);
            network = repmat("nr5g", count, 1);
            carriers = 2 * ones(count, 1);
            last = find(recent);
            % Of the last day's 144 polls: 15 failed, 13 read without
            % service, and of the 116 attached ones 58 were on LTE; each
            % of the 116 had one secondary carrier where the week had two.
            kind(last(1:15)) = "failed";
            kind(last(16:28)) = "no_service";
            network(last(29:86)) = "lte";
            carriers(last(29:144)) = 1;
            samples = radioPolls(testCase.Folder, at, kind, ...
                repmat(testCase.Steady, count, 1), network, carriers);

            [indicators, verdict] = mooring.radioDegradation(samples);

            testCase.verifyEqual(indicators.recent(8:11), [15 / 144; 13 / 129; 0.5; 1], "AbsTol", 1e-12);
            testCase.verifyEqual(indicators.baseline(8:11), [0; 0; 1; 2]);
            testCase.verifyEqual(indicators.change(8:11), [15 / 144; 13 / 129; -0.5; -1], "AbsTol", 1e-12);
            % The share of failed polls is of all polls, the share without
            % service of the polls that read, the last two of the attached.
            testCase.verifyEqual(indicators.recent_count, [116; 116; 116; 116; 0; 0; 0; 144; 129; 116; 116]);
            testCase.verifyEqual(indicators.baseline_count, ...
                [1008; 1008; 1008; 1008; 0; 0; 0; 1008; 1008; 1008; 1008]);
            testCase.verifyEqual(indicators.state, ["ok"; "ok"; "ok"; "ok"; "insufficient_data"; ...
                "insufficient_data"; "insufficient_data"; "degraded"; "degraded"; "degraded"; "degraded"]);
            testCase.verifyEqual(verdict, "degraded");
        end

        function aShareHigherByLessThanItsThresholdIsOk(testCase)
            [at, recent] = testCase.eightDays();
            count = numel(at);
            kind = repmat("attached", count, 1);
            last = find(recent);
            kind(last(1:7)) = "failed";
            samples = radioPolls(testCase.Folder, at, kind, ...
                repmat(testCase.Steady, count, 1), repmat("lte", count, 1), ones(count, 1));
            [indicators, verdict] = mooring.radioDegradation(samples);
            % 7 of 144 is 4.9 %, under the 5 %.
            testCase.verifyEqual(indicators.recent(8), 7 / 144, "AbsTol", 1e-12);
            testCase.verifyEqual(indicators.state(8), "ok");
            testCase.verifyEqual(verdict, "ok");
            % One more is 5.6 %.
            kind(last(8)) = "failed";
            samples = radioPolls(testCase.Folder, at, kind, ...
                repmat(testCase.Steady, count, 1), repmat("lte", count, 1), ones(count, 1));
            [indicators, verdict] = mooring.radioDegradation(samples);
            testCase.verifyEqual(indicators.state(8), "degraded");
            testCase.verifyEqual(verdict, "degraded");
        end

        function tooFewPollsInAWindowAreInsufficientData(testCase)
            % Two hours of polls: twelve in the last day, none before it.
            at = (testCase.Last - 600 * 11:600:testCase.Last)';
            samples = testCase.attachedOnLte(at, repmat(testCase.Steady, 12, 1));
            insufficient = repmat("insufficient_data", 11, 1);

            [indicators, verdict] = mooring.radioDegradation(samples);
            testCase.verifyEqual(indicators.recent_count, [12; 12; 12; 12; 0; 0; 0; 12; 12; 12; 12]);
            testCase.verifyEqual(indicators.baseline_count, zeros(11, 1));
            testCase.verifyEqual(indicators.recent(1:4), [-95; -10; 10; -60]);
            testCase.verifyEqual(indicators.baseline, nan(11, 1));
            testCase.verifyEqual(indicators.state, insufficient);
            testCase.verifyEqual(verdict, "insufficient_data");
            % Enough in the last day is not enough without a baseline.
            [indicators, verdict] = mooring.radioDegradation(samples, MinSamples=5);
            testCase.verifyEqual(indicators.state, insufficient);
            testCase.verifyEqual(verdict, "insufficient_data");

            [indicators, verdict] = mooring.radioDegradation(noRadioSamples(testCase.Folder));
            testCase.verifyEqual(indicators.indicator, testCase.Indicators);
            testCase.verifyEqual(indicators.recent_count, zeros(11, 1));
            testCase.verifyEqual(indicators.baseline_count, zeros(11, 1));
            testCase.verifyEqual(indicators.state, insufficient);
            testCase.verifyEqual(verdict, "insufficient_data");
        end

        function aShortRecentWindowIsComparedWithTheSameHoursOfTheDay(testCase)
            % Every evening from 18:00 UTC the SINR is 5, and 15 the rest
            % of the day. The last six hours are an evening.
            at = testCase.eightDays();
            readings = repmat(testCase.Steady, numel(at), 1);
            readings(:, 3) = 15;
            readings(mod(floor(at / 3600), 24) >= 18, 3) = 5;
            samples = testCase.attachedOnLte(at, readings);

            [indicators, verdict] = mooring.radioDegradation(samples, Recent=hours(6));
            % 36 polls from 18:00 to 23:50, against the 36 of the same
            % hours of each of the seven evenings before: as it was.
            testCase.verifyEqual(indicators.recent_count(3), 36);
            testCase.verifyEqual(indicators.baseline_count(3), 252);
            testCase.verifyEqual(indicators.recent(3), 5);
            testCase.verifyEqual(indicators.baseline(3), 5);
            testCase.verifyEqual(indicators.state(3), "ok");
            testCase.verifyEqual(verdict, "ok");

            % A whole day against whole days holds every hour of the day.
            indicators = mooring.radioDegradation(samples);
            testCase.verifyEqual(indicators.baseline_count(3), 1008);
            testCase.verifyEqual(indicators.baseline(3), 15);
        end

        function theWindowsAndTheThresholdsAreTheCallers(testCase)
            samples = testCase.lowerInTheLastDay();

            [indicators, verdict] = mooring.radioDegradation(samples, RsrqDrop=2.5, SinrDrop=3.5);
            testCase.verifyEqual(indicators.threshold, [3; 2.5; 3.5; 3; 3; 2.5; 3.5; 0.05; 0.05; 0.2; 0.5]);
            testCase.verifyEqual(indicators.state(1:4), ["ok"; "ok"; "ok"; "ok"]);
            testCase.verifyEqual(verdict, "ok");

            indicators = mooring.radioDegradation(samples, RsrpDrop=2.5, RssiDrop=1, ...
                FailedRise=0.5, NoServiceRise=0.6, Nr5gDrop=0.7, CarrierDrop=0.8);
            testCase.verifyEqual(indicators.threshold, [2.5; 2; 3; 1; 2.5; 2; 3; 0.5; 0.6; 0.7; 0.8]);
            testCase.verifyEqual(indicators.state(1:4), ["degraded"; "degraded"; "degraded"; "ok"]);

            % The last day's 144 polls are one too few for 145.
            [indicators, verdict] = mooring.radioDegradation(samples, MinSamples=145);
            testCase.verifyEqual(indicators.state, repmat("insufficient_data", 11, 1));
            testCase.verifyEqual(verdict, "insufficient_data");
            indicators = mooring.radioDegradation(samples, MinSamples=144);
            testCase.verifyEqual(indicators.state(3), "degraded");

            % Three days before the last one hold 432 polls, and the last
            % twelve hours 72.
            indicators = mooring.radioDegradation(samples, Baseline=days(3));
            testCase.verifyEqual(indicators.baseline_count(3), 432);
            indicators = mooring.radioDegradation(samples, Recent=hours(12));
            testCase.verifyEqual(indicators.recent_count(3), 72);

            testCase.verifyError(@() mooring.radioDegradation(samples, Recent=hours(0)), ...
                "mooring:radio:BadWindow");
            testCase.verifyError(@() mooring.radioDegradation(samples, Baseline=-days(1)), ...
                "mooring:radio:BadWindow");
            testCase.verifyError(@() mooring.radioDegradation(samples, MinSamples=0), ...
                "MATLAB:validators:mustBePositive");
            testCase.verifyError(@() mooring.radioDegradation(samples, SinrDrop=0), ...
                "MATLAB:validators:mustBePositive");
        end
    end
end
