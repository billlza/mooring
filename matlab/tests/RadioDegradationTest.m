classdef RadioDegradationTest < matlab.unittest.TestCase
%RADIODEGRADATIONTEST The last day's link against the days before it.

% SPDX-License-Identifier: GPL-3.0-or-later

    properties (Constant)
        % The last poll: 2026-10-13 23:50:00 UTC.
        Last = 1791935400
        Indicators = ["lte_rsrp_dbm"; "lte_rsrq_db"; "lte_sinr_db"; "lte_rssi_dbm"; ...
            "nr_rsrp_dbm"; "nr_rsrq_db"; "nr_sinr_db"; "poll_failed_share"; ...
            "no_service_share"; "nr5g_share"; "ca_secondary_mean"]
        % What every poll reads unless a test says otherwise: LTE only.
        Steady = [-95, -10, 10, -60, NaN, NaN, NaN]
        % The days that count where every day holds polls: none for the
        % NR readings no poll reported.
        SevenDays = [7; 7; 7; 7; 0; 0; 0; 7; 7; 7; 7]
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
        function [at, daysBack] = eightDays(testCase)
            % A poll every ten minutes for eight days: 1152 polls, 144 in
            % each 24 hours counted back from the last poll. `daysBack` is
            % 0 for the last 24 hours and k for the 24 hours k days before.
            at = (testCase.Last - 600 * 1151:600:testCase.Last)';
            daysBack = floor((testCase.Last - at) / 86400);
        end

        function samples = attachedOnLte(testCase, at, readings)
            count = numel(at);
            samples = radioPolls(testCase.Folder, at, repmat("attached", count, 1), ...
                readings, repmat("lte", count, 1), ones(count, 1));
        end

        function samples = sinrByDay(testCase, at, sinr)
            % Steady polls at `at`, with the SINR `sinr` gives each.
            readings = repmat(testCase.Steady, numel(at), 1);
            readings(:, 3) = sinr;
            samples = testCase.attachedOnLte(at, readings);
        end

        function samples = lowerInTheLastDay(testCase)
            % RSRP 2.9 dB lower, RSRQ 2 dB lower and SINR 3 dB lower in
            % the last 24 hours than in the week before.
            [at, daysBack] = testCase.eightDays();
            recent = daysBack == 0;
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
                "baseline", "change", "threshold", "spread", "worse_when", "recent_count", ...
                "baseline_days", "state"]);
            testCase.verifyEqual(indicators.indicator, testCase.Indicators);
            testCase.verifyEqual(indicators.recent, [-97.9; -12; 7; -60; NaN; NaN; NaN; 0; 0; 0; 1]);
            testCase.verifyEqual(indicators.baseline, [-95; -10; 10; -60; NaN; NaN; NaN; 0; 0; 0; 1]);
            testCase.verifyEqual(indicators.change, [-2.9; -2; -3; 0; NaN; NaN; NaN; 0; 0; 0; 0], ...
                "AbsTol", 1e-9);
            testCase.verifyEqual(indicators.threshold, [3; 2; 3; 3; 3; 2; 3; 0.05; 0.05; 0.2; 0.5]);
            % The seven days before are alike.
            testCase.verifyEqual(indicators.spread, [0; 0; 0; 0; NaN; NaN; NaN; 0; 0; 0; 0]);
            testCase.verifyEqual(indicators.worse_when, ...
                [repmat("lower", 7, 1); "higher"; "higher"; "lower"; "lower"]);
            testCase.verifyEqual(indicators.recent_count, [144; 144; 144; 144; 0; 0; 0; 144; 144; 144; 144]);
            testCase.verifyEqual(indicators.baseline_days, testCase.SevenDays);
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
            [at, daysBack] = testCase.eightDays();
            readings = repmat(testCase.Steady, numel(at), 1);
            readings(daysBack == 0, 1:4) = readings(daysBack == 0, 1:4) + 10;
            [indicators, verdict] = mooring.radioDegradation(testCase.attachedOnLte(at, readings));
            testCase.verifyEqual(indicators.change(1:4), [10; 10; 10; 10]);
            testCase.verifyEqual(indicators.state(1:4), ["ok"; "ok"; "ok"; "ok"]);
            testCase.verifyEqual(verdict, "ok");
        end

        function failedPollsLostServiceLess5gAndFewerCarriersAreDegraded(testCase)
            [at, daysBack] = testCase.eightDays();
            count = numel(at);
            kind = repmat("attached", count, 1);
            network = repmat("nr5g", count, 1);
            carriers = 2 * ones(count, 1);
            last = find(daysBack == 0);
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
            testCase.verifyEqual(indicators.baseline_days, testCase.SevenDays);
            testCase.verifyEqual(indicators.state, ["ok"; "ok"; "ok"; "ok"; "insufficient_data"; ...
                "insufficient_data"; "insufficient_data"; "degraded"; "degraded"; "degraded"; "degraded"]);
            testCase.verifyEqual(verdict, "degraded");
        end

        function aShareHigherByLessThanItsThresholdIsOk(testCase)
            [at, daysBack] = testCase.eightDays();
            count = numel(at);
            kind = repmat("attached", count, 1);
            last = find(daysBack == 0);
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

        function aChangeWithinWhatTheDaysDifferByIsOk(testCase)
            % The SINR of the seven days before, the nearest first: 10,
            % 12, 14, 16, 18, 20 and 22. Their median is 16, and they lie
            % 6, 4, 2, 0, 2, 4 and 6 from it: a spread of 4.
            [at, daysBack] = testCase.eightDays();
            sinr = 8 + 2 * daysBack;

            % 12 dB under the baseline is three times the spread, not more.
            sinr(daysBack == 0) = 4;
            samples = testCase.sinrByDay(at, sinr);
            [indicators, verdict] = mooring.radioDegradation(samples);
            testCase.verifyEqual(indicators.recent(3), 4);
            testCase.verifyEqual(indicators.baseline(3), 16);
            testCase.verifyEqual(indicators.change(3), -12);
            testCase.verifyEqual(indicators.spread(3), 4);
            testCase.verifyEqual(indicators.baseline_days(3), 7);
            testCase.verifyEqual(indicators.state(3), "ok");
            testCase.verifyEqual(verdict, "ok");
            % The caller may ask for less than three times, or leave the
            % threshold alone.
            indicators = mooring.radioDegradation(samples, SpreadFactor=2.9);
            testCase.verifyEqual(indicators.state(3), "degraded");
            indicators = mooring.radioDegradation(samples, SpreadFactor=0);
            testCase.verifyEqual(indicators.state(3), "degraded");
            % The spread never makes a change under the threshold count.
            [indicators, verdict] = mooring.radioDegradation(samples, SpreadFactor=0, SinrDrop=12.1);
            testCase.verifyEqual(indicators.state(3), "ok");
            testCase.verifyEqual(verdict, "ok");

            % 12.1 dB under it is more.
            sinr(daysBack == 0) = 3.9;
            [indicators, verdict] = mooring.radioDegradation(testCase.sinrByDay(at, sinr));
            testCase.verifyEqual(indicators.change(3), -12.1, "AbsTol", 1e-9);
            testCase.verifyEqual(indicators.state(3), "degraded");
            testCase.verifyEqual(verdict, "degraded");
        end

        function theBaselineIsTheMedianOfTheDaysAndNotOfTheirPolls(testCase)
            % The three days before the last hold 144 polls each with a
            % SINR of 20; the four days before those hold 36 each (every
            % fourth poll) with a SINR of 10, as the last day has. Most
            % polls read 20; most days read 10.
            [at, daysBack] = testCase.eightDays();
            kept = daysBack <= 3 | mod((testCase.Last - at) / 600, 4) == 0;
            at = at(kept);
            daysBack = daysBack(kept);
            sinr = 10 * ones(numel(at), 1);
            sinr(daysBack >= 1 & daysBack <= 3) = 20;

            [indicators, verdict] = mooring.radioDegradation(testCase.sinrByDay(at, sinr));
            testCase.verifyEqual(indicators.recent_count(3), 144);
            testCase.verifyEqual(indicators.baseline_days(3), 7);
            testCase.verifyEqual(indicators.baseline(3), 10);
            testCase.verifyEqual(indicators.change(3), 0);
            % Four of the seven days are on the baseline.
            testCase.verifyEqual(indicators.spread(3), 0);
            testCase.verifyEqual(indicators.state(3), "ok");
            testCase.verifyEqual(verdict, "ok");
        end

        function aLinkThatStaysWorseIsDegradedUntilMostOfTheBaselineIsAsBad(testCase)
            % The SINR was 10 and is 4 for the last day and the three
            % days before it: four of the baseline's seven days still
            % read 10.
            [at, daysBack] = testCase.eightDays();
            sinr = 10 * ones(numel(at), 1);
            sinr(daysBack <= 3) = 4;
            [indicators, verdict] = mooring.radioDegradation(testCase.sinrByDay(at, sinr));
            testCase.verifyEqual(indicators.baseline(3), 10);
            testCase.verifyEqual(indicators.change(3), -6);
            testCase.verifyEqual(indicators.spread(3), 0);
            testCase.verifyEqual(indicators.state(3), "degraded");
            testCase.verifyEqual(verdict, "degraded");

            % One day more, and four of the seven read 4: the baseline.
            sinr(daysBack <= 4) = 4;
            [indicators, verdict] = mooring.radioDegradation(testCase.sinrByDay(at, sinr));
            testCase.verifyEqual(indicators.baseline(3), 4);
            testCase.verifyEqual(indicators.change(3), 0);
            testCase.verifyEqual(indicators.state(3), "ok");
            testCase.verifyEqual(verdict, "ok");
        end

        function tooFewPollsInTheRecentWindowAreInsufficientData(testCase)
            % Two hours of polls: twelve in the last day, none before it.
            at = (testCase.Last - 600 * 11:600:testCase.Last)';
            samples = testCase.attachedOnLte(at, repmat(testCase.Steady, 12, 1));
            insufficient = repmat("insufficient_data", 11, 1);

            [indicators, verdict] = mooring.radioDegradation(samples);
            testCase.verifyEqual(indicators.recent_count, [12; 12; 12; 12; 0; 0; 0; 12; 12; 12; 12]);
            testCase.verifyEqual(indicators.baseline_days, zeros(11, 1));
            testCase.verifyEqual(indicators.recent(1:4), [-95; -10; 10; -60]);
            testCase.verifyEqual(indicators.baseline, nan(11, 1));
            testCase.verifyEqual(indicators.spread, nan(11, 1));
            testCase.verifyEqual(indicators.state, insufficient);
            testCase.verifyEqual(verdict, "insufficient_data");
            % Enough in the last day is not enough without a baseline.
            [indicators, verdict] = mooring.radioDegradation(samples, MinSamples=5);
            testCase.verifyEqual(indicators.state, insufficient);
            testCase.verifyEqual(verdict, "insufficient_data");

            % Seven days that count are not enough with 29 polls in the
            % last day, its latest. With 30 they are.
            [at, daysBack] = testCase.eightDays();
            last = find(daysBack == 0);
            few = true(numel(at), 1);
            few(last(1:115)) = false;
            samples = testCase.attachedOnLte(at(few), repmat(testCase.Steady, sum(few), 1));
            [indicators, verdict] = mooring.radioDegradation(samples);
            testCase.verifyEqual(indicators.recent_count, [29; 29; 29; 29; 0; 0; 0; 29; 29; 29; 29]);
            testCase.verifyEqual(indicators.baseline_days, testCase.SevenDays);
            testCase.verifyEqual(indicators.state, insufficient);
            testCase.verifyEqual(verdict, "insufficient_data");
            few(last(115)) = true;
            samples = testCase.attachedOnLte(at(few), repmat(testCase.Steady, sum(few), 1));
            [indicators, verdict] = mooring.radioDegradation(samples);
            testCase.verifyEqual(indicators.recent_count, [30; 30; 30; 30; 0; 0; 0; 30; 30; 30; 30]);
            testCase.verifyEqual(indicators.state, ["ok"; "ok"; "ok"; "ok"; ...
                "insufficient_data"; "insufficient_data"; "insufficient_data"; "ok"; "ok"; "ok"; "ok"]);
            testCase.verifyEqual(verdict, "ok");

            [indicators, verdict] = mooring.radioDegradation(noRadioSamples(testCase.Folder));
            testCase.verifyEqual(indicators.indicator, testCase.Indicators);
            testCase.verifyEqual(indicators.recent_count, zeros(11, 1));
            testCase.verifyEqual(indicators.baseline_days, zeros(11, 1));
            testCase.verifyEqual(indicators.state, insufficient);
            testCase.verifyEqual(verdict, "insufficient_data");
        end

        function tooFewEarlierDaysAreInsufficientData(testCase)
            % Four days of polls: the last one and three before it.
            at = (testCase.Last - 600 * 575:600:testCase.Last)';
            daysBack = floor((testCase.Last - at) / 86400);
            sinr = 10 * ones(numel(at), 1);
            sinr(daysBack == 0) = 4;
            judged = ["ok"; "ok"; "degraded"; "ok"; "insufficient_data"; "insufficient_data"; ...
                "insufficient_data"; "ok"; "ok"; "ok"; "ok"];

            [indicators, verdict] = mooring.radioDegradation(testCase.sinrByDay(at, sinr));
            testCase.verifyEqual(indicators.baseline_days, [3; 3; 3; 3; 0; 0; 0; 3; 3; 3; 3]);
            testCase.verifyEqual(indicators.state, judged);
            testCase.verifyEqual(verdict, "degraded");

            % The day two days back holds 30 polls: it counts.
            thin = find(daysBack == 2);
            few = true(numel(at), 1);
            few(thin(31:end)) = false;
            [indicators, verdict] = mooring.radioDegradation(testCase.sinrByDay(at(few), sinr(few)));
            testCase.verifyEqual(indicators.baseline_days, [3; 3; 3; 3; 0; 0; 0; 3; 3; 3; 3]);
            testCase.verifyEqual(verdict, "degraded");
            % With 29 it does not, and two days are too few to judge by.
            few(thin(30)) = false;
            [indicators, verdict] = mooring.radioDegradation(testCase.sinrByDay(at(few), sinr(few)));
            testCase.verifyEqual(indicators.baseline_days, [2; 2; 2; 2; 0; 0; 0; 2; 2; 2; 2]);
            testCase.verifyEqual(indicators.baseline(3), 10);
            testCase.verifyEqual(indicators.change(3), -6);
            testCase.verifyEqual(indicators.state, repmat("insufficient_data", 11, 1));
            testCase.verifyEqual(verdict, "insufficient_data");
            % Unless the caller takes two.
            [indicators, verdict] = mooring.radioDegradation(testCase.sinrByDay(at(few), sinr(few)), ...
                MinDays=2);
            testCase.verifyEqual(indicators.state, judged);
            testCase.verifyEqual(verdict, "degraded");
        end

        function aShortRecentWindowIsComparedWithTheSameHoursOfTheDay(testCase)
            % Every evening from 18:00 UTC the SINR is 5, and 15 the rest
            % of the day. The last six hours are an evening.
            at = testCase.eightDays();
            sinr = 15 * ones(numel(at), 1);
            sinr(mod(floor(at / 3600), 24) >= 18) = 5;
            samples = testCase.sinrByDay(at, sinr);

            [indicators, verdict] = mooring.radioDegradation(samples, Recent=hours(6));
            % 36 polls from 18:00 to 23:50, against the same hours of each
            % of the seven evenings before: as it was.
            testCase.verifyEqual(indicators.recent_count(3), 36);
            testCase.verifyEqual(indicators.baseline_days(3), 7);
            testCase.verifyEqual(indicators.recent(3), 5);
            testCase.verifyEqual(indicators.baseline(3), 5);
            testCase.verifyEqual(indicators.state(3), "ok");
            testCase.verifyEqual(verdict, "ok");

            % A whole day against whole days holds every hour of the day.
            indicators = mooring.radioDegradation(samples);
            testCase.verifyEqual(indicators.recent(3), 15);
            testCase.verifyEqual(indicators.baseline(3), 15);
        end

        function aWindowHoldsItsOwnHoursAndNoOther(testCase)
            % Every poll from 18:00 UTC to the day's end is attached and
            % every other poll failed, so that one poll of another hour in
            % a window shows in the window's share of failed polls.
            at = testCase.eightDays();
            count = numel(at);
            kind = repmat("failed", count, 1);
            kind(mod(floor(at / 3600), 24) >= 18) = "attached";
            samples = radioPolls(testCase.Folder, at, kind, ...
                repmat(testCase.Steady, count, 1), repmat("lte", count, 1), ones(count, 1));

            indicators = mooring.radioDegradation(samples, Recent=hours(6));
            testCase.verifyEqual(indicators.recent_count(8), 36);
            testCase.verifyEqual(indicators.recent(8), 0);
            testCase.verifyEqual(indicators.baseline(8), 0);
            testCase.verifyEqual(indicators.baseline_days(8), 7);

            % Ten minutes more reach the poll of 17:50, in each window.
            indicators = mooring.radioDegradation(samples, Recent=hours(6) + minutes(10));
            testCase.verifyEqual(indicators.recent_count(8), 37);
            testCase.verifyEqual(indicators.recent(8), 1 / 37, "AbsTol", 1e-12);
            testCase.verifyEqual(indicators.baseline(8), 1 / 37, "AbsTol", 1e-12);
            testCase.verifyEqual(indicators.spread(8), 0);

            % A whole day holds the day's 108 failed polls of 144.
            indicators = mooring.radioDegradation(samples);
            testCase.verifyEqual(indicators.recent_count(8), 144);
            testCase.verifyEqual(indicators.recent(8), 0.75);
            testCase.verifyEqual(indicators.baseline(8), 0.75);
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

            % A threshold of Inf leaves its readings out.
            indicators = mooring.radioDegradation(samples, SinrDrop=Inf);
            testCase.verifyEqual(indicators.state(1:4), ["ok"; "degraded"; "ok"; "ok"]);

            % The last day's 144 polls are one too few for 145.
            [indicators, verdict] = mooring.radioDegradation(samples, MinSamples=145);
            testCase.verifyEqual(indicators.state, repmat("insufficient_data", 11, 1));
            testCase.verifyEqual(verdict, "insufficient_data");
            indicators = mooring.radioDegradation(samples, MinSamples=144);
            testCase.verifyEqual(indicators.state(3), "degraded");

            % Three days before the last one, and the last twelve hours.
            indicators = mooring.radioDegradation(samples, Days=3);
            testCase.verifyEqual(indicators.baseline_days, [3; 3; 3; 3; 0; 0; 0; 3; 3; 3; 3]);
            testCase.verifyEqual(indicators.state(3), "degraded");
            indicators = mooring.radioDegradation(samples, Days=1, MinDays=1);
            testCase.verifyEqual(indicators.baseline_days(3), 1);
            testCase.verifyEqual(indicators.state(3), "degraded");
            indicators = mooring.radioDegradation(samples, Recent=hours(12));
            testCase.verifyEqual(indicators.recent_count(3), 72);
            indicators = mooring.radioDegradation(samples, Recent=hours(24));
            testCase.verifyEqual(indicators.recent_count(3), 144);

            testCase.verifyError(@() mooring.radioDegradation(samples, Recent=hours(0)), ...
                "mooring:radio:BadWindow");
            testCase.verifyError(@() mooring.radioDegradation(samples, Recent=-hours(1)), ...
                "mooring:radio:BadWindow");
            testCase.verifyError(@() mooring.radioDegradation(samples, Recent=hours(24) + seconds(1)), ...
                "mooring:radio:BadWindow");
            testCase.verifyError(@() mooring.radioDegradation(samples, Recent=hours(NaN)), ...
                "mooring:radio:BadWindow");
            % The default asks for three days that count.
            testCase.verifyError(@() mooring.radioDegradation(samples, Days=2), ...
                "mooring:radio:BadWindow");
            testCase.verifyError(@() mooring.radioDegradation(samples, MinDays=8), ...
                "mooring:radio:BadWindow");
            testCase.verifyError(@() mooring.radioDegradation(samples, Days=0), ...
                "MATLAB:validators:mustBePositive");
            testCase.verifyError(@() mooring.radioDegradation(samples, MinDays=0), ...
                "MATLAB:validators:mustBePositive");
            testCase.verifyError(@() mooring.radioDegradation(samples, MinSamples=0), ...
                "MATLAB:validators:mustBePositive");
            testCase.verifyError(@() mooring.radioDegradation(samples, SinrDrop=0), ...
                "MATLAB:validators:mustBePositive");
            testCase.verifyError(@() mooring.radioDegradation(samples, SpreadFactor=-1), ...
                "MATLAB:validators:mustBeNonnegative");
            testCase.verifyError(@() mooring.radioDegradation(samples, SpreadFactor=Inf), ...
                "MATLAB:validators:mustBeFinite");
        end
    end
end
