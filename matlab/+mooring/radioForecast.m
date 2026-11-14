function [forecast, fit] = radioForecast(samples, options)
%RADIOFORECAST The coming hours of a reading, from its trend and daily pattern.
%   FORECAST = mooring.radioForecast(SAMPLES) forecasts the hourly median
%   of the LTE SINR for the 48 hours after the last sample of SAMPLES (the
%   timetable mooring.readRadioSamples returns), from the hourly medians
%   of the 14 days before (mooring.radioHourly). FORECAST is a timetable
%   with a row per coming hour, `hour` being the hour's start in UTC:
%
%     expected   the forecast of the hour's median
%     low, high  expected plus the 10 % and the 90 % quantile of what the
%                history's hours differ from the fit by
%
%   The fit is a straight trend plus a level for each hour of the day
%   (mooring.internal.seasonalTrend). It is a description of the history
%   continued, and knows nothing of what changes a link: another band,
%   another network or cell, the M7 moved. The band between low and high
%   holds 80 % of the history's hours around the fit and does not widen
%   with the distance ahead. An hour of the day the history never held has
%   no forecast: NaN.
%
%   [FORECAST, FIT] = mooring.radioForecast(...) also returns what was
%   fitted and how well it did on the history's own last hours:
%
%     metric          the reading
%     hours           how many hourly medians the fit used
%     slope_per_day   the trend, in the reading's unit per day
%     profile         24 by 1: the level of each hour of the day, 00 to
%                     23 UTC, at the history's last hour
%     residual_low, residual_high
%                     the two quantiles above
%     backtest_hours  how many hours a backtest scored: the fit made
%                     without the history's last Horizon, compared with
%                     them; 0 when too few hours are left to fit
%     backtest_mae    the mean absolute error of that fit over them
%     naive_mae       the same for the forecast "as at the same hour of
%                     the last day before": the fit earns trust where its
%                     error is the smaller of the two
%
%   Name-value arguments:
%     Metric    the reading: "lte_rsrp_dbm", "lte_rsrq_db", "lte_sinr_db"
%               (default), "lte_rssi_dbm", "nr_rsrp_dbm", "nr_rsrq_db" or
%               "nr_sinr_db"
%     Horizon   how far ahead, in whole hours (default hours(48))
%     History   how far back the fit looks (default days(14))
%     MinHours  the fewest hourly medians a fit needs, at least 48
%               (default 72); with fewer the function throws
%               mooring:radio:TooFewHours
%
%   See also mooring.radioHourly, mooring.radioDegradation.

% SPDX-License-Identifier: GPL-3.0-or-later

    arguments
        samples timetable {mooring.internal.mustBeSamples}
        options.Metric (1,1) string = "lte_sinr_db"
        options.Horizon (1,1) duration = hours(48)
        options.History (1,1) duration = days(14)
        options.MinHours (1,1) double {mustBeInteger, mustBeGreaterThanOrEqual(options.MinHours, 48)} = 72
    end
    readings = mooring.internal.radioReadings();
    if ~ismember(options.Metric, readings)
        error("mooring:radio:UnknownMetric", ...
            "%s is not a reading. The readings are %s.", options.Metric, join(readings, ", "));
    end
    horizon = floor(hours(options.Horizon));
    if horizon < 1
        error("mooring:radio:BadHorizon", "The horizon is shorter than an hour; a forecast is by the hour.");
    end

    hourly = mooring.radioHourly(samples);
    values = hourly.(options.Metric);
    starts = hourly.Properties.RowTimes;
    kept = max(1, numel(values) - floor(hours(options.History)) + 1):numel(values);
    values = values(kept);
    starts = starts(kept);
    known = ~isnan(values);
    if sum(known) < options.MinHours
        error("mooring:radio:TooFewHours", ...
            "%d of the last %d hours hold a %s reading; a forecast needs %d.", ...
            sum(known), numel(values), options.Metric, options.MinHours);
    end

    % Hours are counted from the history's last one, so that the profile
    % is each hour of the day's level now.
    offset = (1 - numel(values):0)';
    hourOfDay = hour(starts);
    [slope, profile] = mooring.internal.seasonalTrend(offset(known), hourOfDay(known), values(known));
    residual = mooring.internal.quantiles( ...
        values - (slope * offset + profile(hourOfDay + 1)), [0.1 0.9]);
    ahead = (1:horizon)';
    comingHours = starts(end) + hours(ahead);
    expected = slope * ahead + profile(hour(comingHours) + 1);
    forecast = timetable(comingHours, expected, expected + residual(1), expected + residual(2), ...
        'VariableNames', {'expected', 'low', 'high'});
    forecast.Properties.DimensionNames{1} = 'hour';

    fit.metric = options.Metric;
    fit.hours = sum(known);
    fit.slope_per_day = 24 * slope;
    fit.profile = profile;
    fit.residual_low = residual(1);
    fit.residual_high = residual(2);
    fit.backtest_hours = 0;
    fit.backtest_mae = NaN;
    fit.naive_mae = NaN;
    held = offset > -horizon;
    earlier = known & ~held;
    if sum(earlier) >= options.MinHours
        [earlierSlope, earlierProfile] = mooring.internal.seasonalTrend( ...
            offset(earlier), hourOfDay(earlier), values(earlier));
        fitted = earlierSlope * offset(held) + earlierProfile(hourOfDay(held) + 1);
        % The naive forecast: each hour of the day as it last was. The
        % rows are in the order of time, so the latest of an hour of the
        % day is the one with the highest index.
        rows = find(earlier);
        latest = accumarray(hourOfDay(rows) + 1, rows, [24 1], @max, NaN);
        lastSeen = nan(24, 1);
        lastSeen(~isnan(latest)) = values(latest(~isnan(latest)));
        naive = lastSeen(hourOfDay(held) + 1);
        actual = values(held);
        scored = ~isnan(actual) & ~isnan(fitted) & ~isnan(naive);
        fit.backtest_hours = sum(scored);
        fit.backtest_mae = mean(abs(actual(scored) - fitted(scored)));
        fit.naive_mae = mean(abs(actual(scored) - naive(scored)));
    end
end
