classdef RadioForecastTest < matlab.unittest.TestCase
%RADIOFORECASTTEST The coming hours, from the trend and the daily pattern.

% SPDX-License-Identifier: GPL-3.0-or-later

    properties (Constant)
        % The start of the last hour: 2026-10-13 23:00:00 UTC.
        LastHour = 1791932400
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
        function samples = hourly(testCase, sinr)
            % One SINR per hour, the last of them for the hour from 23:00
            % on 2026-10-13: two attached polls in each hour, ten and
            % forty minutes past it, both with the hour's SINR; no poll in
            % an hour whose SINR is NaN. The RSRP is -100 throughout.
            start = testCase.LastHour - 3600 * (numel(sinr) - 1:-1:0)';
            polled = ~isnan(sinr);
            at = [start(polled) + 600; start(polled) + 2400];
            count = numel(at);
            readings = [repmat([-100, -12], count, 1), [sinr(polled); sinr(polled)], ...
                repmat([-70, NaN, NaN, NaN], count, 1)];
            samples = radioPolls(testCase.Folder, at, repmat("attached", count, 1), ...
                readings, repmat("lte", count, 1), zeros(count, 1));
        end
    end

    methods (Static)
        function dip = evening(hourOfDay)
            % 3 dB lower from 18:00 to 21:59 UTC.
            dip = -3 * (hourOfDay >= 18 & hourOfDay <= 21);
        end

        function sinr = rising(count)
            % `count` hours ending with the one from 23:00: 20 dB then,
            % 0.1 dB less each hour before, and the evening's dip.
            offset = (1 - count:0)';
            sinr = 20 + 0.1 * offset + RadioForecastTest.evening(mod(23 + offset, 24));
        end
    end

    methods (Test)
        function theTrendAndTheDailyPatternAreContinued(testCase)
            [forecast, fit] = mooring.radioForecast(testCase.hourly(RadioForecastTest.rising(240)));

            ahead = (1:48)';
            expected = 20 + 0.1 * ahead + RadioForecastTest.evening(mod(23 + ahead, 24));
            testCase.verifyClass(forecast, "timetable");
            testCase.verifyEqual(string(forecast.Properties.VariableNames), ["expected", "low", "high"]);
            testCase.verifyEqual(string(forecast.Properties.DimensionNames{1}), "hour");
            testCase.verifyEqual(string(forecast.hour.TimeZone), "UTC");
            testCase.verifyEqual(posixtime(forecast.hour), testCase.LastHour + 3600 * ahead);
            testCase.verifyEqual(forecast.expected, expected, "AbsTol", 1e-9);
            % Every hour of the history is on the fit, so the band is the fit.
            testCase.verifyEqual(forecast.low, expected, "AbsTol", 1e-9);
            testCase.verifyEqual(forecast.high, expected, "AbsTol", 1e-9);

            testCase.verifyEqual(sort(string(fieldnames(fit)))', sort(["metric", "hours", "slope_per_day", ...
                "profile", "residual_low", "residual_high", "backtest_hours", "backtest_mae", "naive_mae"]));
            testCase.verifyEqual(fit.metric, "lte_sinr_db");
            testCase.verifyEqual(fit.hours, 240);
            testCase.verifyEqual(fit.slope_per_day, 2.4, "AbsTol", 1e-9);
            % The profile is each hour of the day's level at the last hour.
            testCase.verifyEqual(fit.profile, 20 + RadioForecastTest.evening((0:23)'), "AbsTol", 1e-9);
            testCase.verifyEqual(fit.residual_low, 0, "AbsTol", 1e-9);
            testCase.verifyEqual(fit.residual_high, 0, "AbsTol", 1e-9);
            % Without the last 48 hours the same fit forecasts them
            % exactly. "As at the same hour of the last day before" is 2.4
            % dB under the first held day and 4.8 dB under the second.
            testCase.verifyEqual(fit.backtest_hours, 48);
            testCase.verifyEqual(fit.backtest_mae, 0, "AbsTol", 1e-9);
            testCase.verifyEqual(fit.naive_mae, 3.6, "AbsTol", 1e-9);
        end

        function oneHourFarFromTheOthersMovesNothing(testCase)
            sinr = RadioForecastTest.rising(240);
            plain = mooring.radioForecast(testCase.hourly(sinr));
            sinr(100) = sinr(100) + 30;
            [forecast, fit] = mooring.radioForecast(testCase.hourly(sinr));

            testCase.verifyEqual(forecast.expected, plain.expected, "AbsTol", 1e-9);
            testCase.verifyEqual(fit.slope_per_day, 2.4, "AbsTol", 1e-9);
            testCase.verifyEqual(fit.profile, 20 + RadioForecastTest.evening((0:23)'), "AbsTol", 1e-9);
            testCase.verifyEqual(fit.residual_high, 0, "AbsTol", 1e-9);
            testCase.verifyEqual(fit.backtest_mae, 0, "AbsTol", 1e-9);
        end

        function theBandIsWhereTheHistorysHoursLayAroundTheFit(testCase)
            % Every fifth hour 1 dB over the pattern, every fifth 2 dB
            % under it, in an order that repeats every five days.
            sinr = RadioForecastTest.rising(240) - 0.1 * (-239:0)';
            index = (1:240)';
            sinr(mod(index, 5) == 0) = sinr(mod(index, 5) == 0) + 1;
            sinr(mod(index, 5) == 1) = sinr(mod(index, 5) == 1) - 2;
            [forecast, fit] = mooring.radioForecast(testCase.hourly(sinr));

            % Each hour of the day holds ten values: two over, two under
            % and six on the pattern, so the fit is the pattern and a
            % fifth of the hours lie on each side of it.
            testCase.verifyEqual(fit.slope_per_day, 0, "AbsTol", 1e-9);
            testCase.verifyEqual(fit.profile, 20 + RadioForecastTest.evening((0:23)'), "AbsTol", 1e-9);
            testCase.verifyEqual(fit.residual_low, -2, "AbsTol", 1e-9);
            testCase.verifyEqual(fit.residual_high, 1, "AbsTol", 1e-9);
            testCase.verifyEqual(forecast.low, forecast.expected - 2, "AbsTol", 1e-9);
            testCase.verifyEqual(forecast.high, forecast.expected + 1, "AbsTol", 1e-9);
        end

        function anHourOfTheDayTheHistoryNeverHeldHasNoForecast(testCase)
            % Polls only from 00:00 to 11:59 UTC of each of ten days.
            offset = (-239:0)';
            sinr = RadioForecastTest.rising(240);
            sinr(mod(23 + offset, 24) >= 12) = NaN;
            [forecast, fit] = mooring.radioForecast(testCase.hourly(sinr));

            % The last sample's hour is the one from 11:00.
            testCase.verifyEqual(posixtime(forecast.hour), testCase.LastHour - 12 * 3600 + 3600 * (1:48)');
            afternoon = hour(forecast.hour) >= 12;
            testCase.verifyEqual(sum(afternoon), 24);
            testCase.verifyEqual(isnan(forecast.expected), afternoon);
            testCase.verifyEqual(isnan(forecast.low), afternoon);
            testCase.verifyEqual(isnan(forecast.high), afternoon);
            ahead = (1:48)';
            testCase.verifyEqual(forecast.expected(~afternoon), 20 + 0.1 * (ahead(~afternoon) - 12), ...
                "AbsTol", 1e-9);
            testCase.verifyEqual(fit.hours, 120);
            testCase.verifyEqual(isnan(fit.profile), (0:23)' >= 12);
            % The backtest scores the hours it has on both sides.
            testCase.verifyEqual(fit.backtest_hours, 24);
            testCase.verifyEqual(fit.backtest_mae, 0, "AbsTol", 1e-9);
            testCase.verifyEqual(fit.naive_mae, 3.6, "AbsTol", 1e-9);
        end

        function tooFewHoursAreRefused(testCase)
            few = testCase.hourly(RadioForecastTest.rising(71));
            try
                mooring.radioForecast(few);
                testCase.verifyFail("A forecast was made.");
            catch failure
                testCase.verifyEqual(string(failure.identifier), "mooring:radio:TooFewHours");
                testCase.verifySubstring(failure.message, "71 of the last 71 hours hold a lte_sinr_db reading");
                testCase.verifySubstring(failure.message, "needs 72");
            end
            % The caller may ask for less, down to two days.
            [forecast, fit] = mooring.radioForecast(few, MinHours=48);
            testCase.verifyEqual(height(forecast), 48);
            testCase.verifyEqual(fit.hours, 71);
            testCase.verifyEqual(fit.slope_per_day, 2.4, "AbsTol", 1e-9);
            % Too few hours are left to fit without the last 48.
            testCase.verifyEqual(fit.backtest_hours, 0);
            testCase.verifyEqual(fit.backtest_mae, NaN);
            testCase.verifyEqual(fit.naive_mae, NaN);
            testCase.verifyError(@() mooring.radioForecast(few, MinHours=47), ...
                "MATLAB:validators:mustBeGreaterThanOrEqual");

            testCase.verifyError(@() mooring.radioForecast(testCase.hourly(RadioForecastTest.rising(72)), ...
                Metric="nr_sinr_db"), "mooring:radio:TooFewHours");
            testCase.verifyError(@() mooring.radioForecast(noRadioSamples(testCase.Folder)), ...
                "mooring:radio:TooFewHours");
        end

        function theHistoryLookedAtIsTheCallers(testCase)
            samples = testCase.hourly(RadioForecastTest.rising(480));
            [~, fit] = mooring.radioForecast(samples);
            testCase.verifyEqual(fit.hours, 336);
            [~, fit] = mooring.radioForecast(samples, History=days(10));
            testCase.verifyEqual(fit.hours, 240);
            [~, fit] = mooring.radioForecast(samples, History=hours(100));
            testCase.verifyEqual(fit.hours, 100);
            testCase.verifyError(@() mooring.radioForecast(samples, History=hours(71)), ...
                "mooring:radio:TooFewHours");
        end

        function theReadingAndTheHorizonAreTheCallers(testCase)
            samples = testCase.hourly(RadioForecastTest.rising(240));

            [forecast, fit] = mooring.radioForecast(samples, Metric="lte_rsrp_dbm", Horizon=hours(5));
            testCase.verifyEqual(fit.metric, "lte_rsrp_dbm");
            testCase.verifyEqual(posixtime(forecast.hour), testCase.LastHour + 3600 * (1:5)');
            testCase.verifyEqual(forecast.expected, repmat(-100, 5, 1), "AbsTol", 1e-9);
            testCase.verifyEqual(fit.slope_per_day, 0, "AbsTol", 1e-9);
            testCase.verifyEqual(fit.backtest_hours, 5);

            % A horizon is in whole hours.
            forecast = mooring.radioForecast(samples, Horizon=minutes(90));
            testCase.verifyEqual(height(forecast), 1);
            testCase.verifyError(@() mooring.radioForecast(samples, Horizon=minutes(59)), ...
                "mooring:radio:BadHorizon");
            testCase.verifyError(@() mooring.radioForecast(samples, Horizon=-hours(3)), ...
                "mooring:radio:BadHorizon");
            try
                mooring.radioForecast(samples, Metric="polls");
                testCase.verifyFail("A forecast was made.");
            catch failure
                testCase.verifyEqual(string(failure.identifier), "mooring:radio:UnknownMetric");
                testCase.verifySubstring(failure.message, "lte_rsrp_dbm, lte_rsrq_db, lte_sinr_db");
            end
        end

        function theTrendIsTheMedianSlopeBetweenTheSameHoursOfTheDay(testCase)
            trend = @mooring.internal.seasonalTrend;
            % Two days: an eighth more each hour, on a level that is the
            % hour of the day.
            offset = (0:47)';
            [slope, profile] = trend(offset, mod(offset, 24), 0.125 * offset + mod(offset, 24));
            testCase.verifyEqual(slope, 0.125);
            testCase.verifyEqual(profile, (0:23)');

            % Three days of two hours each: the three slopes of an hour of
            % the day's pairs, and the median of the six.
            offset = [0; 1; 24; 25; 48; 49];
            values = [0; 10; 24; 34; 96; 106];
            [slope, profile] = trend(offset, mod(offset, 24), values);
            testCase.verifyEqual(slope, 2);
            testCase.verifyEqual(profile(1:2), [0; 8]);
            testCase.verifyEqual(isnan(profile), (0:23)' >= 2);

            % No two values of one hour of the day: no trend to take.
            offset = (0:23)';
            [slope, profile] = trend(offset, offset, offset);
            testCase.verifyEqual(slope, NaN);
            testCase.verifyEqual(profile, nan(24, 1));
        end
    end
end
