function [indicators, verdict] = radioDegradation(samples, options)
%RADIODEGRADATION Whether the radio link is worse than on its own earlier days.
%   [INDICATORS, VERDICT] = mooring.radioDegradation(SAMPLES) compares the
%   last 24 hours of SAMPLES (the timetable mooring.readRadioSamples
%   returns), counted back from the last sample, with the same 24 hours of
%   each of the 7 days before them. A recent window shorter than a day is
%   compared with the same hours of each earlier day, and not with that
%   day's busier or quieter ones.
%
%   INDICATORS is a table with a row per indicator:
%
%     lte_rsrp_dbm ... nr_sinr_db   the median of the polls that hold the
%                                   reading
%     poll_failed_share             the share of the polls that failed
%     no_service_share              the share of the reads without service
%     nr5g_share                    the share of the attached polls on 5G
%     ca_secondary_mean             the mean number of secondary carriers
%                                   of the attached polls
%
%   and these variables:
%
%     recent         the indicator over the recent window
%     baseline       the median of the indicator over each earlier day's
%                    window: what a usual day shows
%     change         recent less baseline
%     threshold      the change that matters (a name-value argument)
%     spread         the median of how far the earlier days lie from the
%                    baseline: how much the link's days differ anyway
%     worse_when     "lower" or "higher"
%     recent_count   the polls with a value in the recent window
%     baseline_days  the earlier days that count: those whose window holds
%                    MinSamples polls with a value or more
%     state          "degraded", "ok" or "insufficient_data"
%
%   An indicator is degraded when it is worse than the baseline by its
%   threshold or more, and by more than SpreadFactor times the spread. So
%   a share that swings from day to day is not degraded by one more swing,
%   and a link that became worse and stays worse is degraded until most of
%   the baseline's days are as bad. An indicator is insufficient_data when
%   the recent window holds fewer polls with a value than MinSamples, or
%   when fewer earlier days than MinDays count. Otherwise it is ok.
%
%   VERDICT is "degraded" when an indicator is degraded, else "ok" when
%   one is ok, else "insufficient_data".
%
%   The thresholds are starting points and not measurements of this link:
%   compare them with what INDICATORS shows over quiet weeks, and set your
%   own. A change of band or of network moves the readings' level without
%   the link being worse or better; mooring.readRadioEvents shows those
%   changes.
%
%   Name-value arguments:
%     Recent         the recent window, 24 hours at most (default
%                    hours(24))
%     Days           how many days before it make the baseline (default 7)
%     MinSamples     the fewest polls with a value a window needs
%                    (default 30)
%     MinDays        the fewest earlier days that must count, Days at most
%                    (default 3)
%     SpreadFactor   how many times the spread a change must exceed
%                    (default 3: about two standard deviations of days
%                    scattered like a normal distribution); with 0 the
%                    thresholds decide alone
%     RsrpDrop       dB the median RSRP falls by (default 3)
%     RsrqDrop       dB the median RSRQ falls by (default 2)
%     SinrDrop       dB the median SINR falls by (default 3)
%     RssiDrop       dB the median RSSI falls by (default 3)
%     FailedRise     what the share of failed polls rises by (default 0.05)
%     NoServiceRise  what the share of reads without service rises by
%                    (default 0.05)
%     Nr5gDrop       what the share on 5G falls by (default 0.2)
%     CarrierDrop    what the mean number of secondary carriers falls by
%                    (default 0.5)
%   A threshold of Inf never calls its indicators degraded.
%
%   See also mooring.readRadioSamples, mooring.radioForecast.

% SPDX-License-Identifier: GPL-3.0-or-later

    arguments
        samples timetable {mooring.internal.mustBeSamples}
        options.Recent (1,1) duration = hours(24)
        options.Days (1,1) double {mustBeInteger, mustBePositive} = 7
        options.MinSamples (1,1) double {mustBeInteger, mustBePositive} = 30
        options.MinDays (1,1) double {mustBeInteger, mustBePositive} = 3
        options.SpreadFactor (1,1) double {mustBeFinite, mustBeNonnegative} = 3
        options.RsrpDrop (1,1) double {mustBePositive} = 3
        options.RsrqDrop (1,1) double {mustBePositive} = 2
        options.SinrDrop (1,1) double {mustBePositive} = 3
        options.RssiDrop (1,1) double {mustBePositive} = 3
        options.FailedRise (1,1) double {mustBePositive} = 0.05
        options.NoServiceRise (1,1) double {mustBePositive} = 0.05
        options.Nr5gDrop (1,1) double {mustBePositive} = 0.2
        options.CarrierDrop (1,1) double {mustBePositive} = 0.5
    end
    if ~(options.Recent > seconds(0) && options.Recent <= hours(24))
        error("mooring:radio:BadWindow", "Recent is a length of time above zero, of 24 hours at most.");
    end
    if options.MinDays > options.Days
        error("mooring:radio:BadWindow", ...
            "MinDays is %d and Days %d: no baseline could count.", options.MinDays, options.Days);
    end

    % Which window each poll is in: 0 for the recent one, k for the same
    % hours k days before it, NaN for a poll in none of them.
    times = samples.Properties.RowTimes;
    back = nan(size(times));
    if ~isempty(times)
        age = max(times) - times;
        wholeDays = floor(age ./ days(1));
        inside = age - days(wholeDays) < options.Recent & wholeDays <= options.Days;
        back(inside) = wholeDays(inside);
    end

    % One column per indicator: NaN where a poll is not of the indicator's
    % population.
    read = samples.outcome == "read";
    attached = samples.service == "attached";
    noService = double(samples.service == "no_service");
    noService(~read) = NaN;
    nr5g = double(samples.network_service == "nr5g");
    nr5g(~attached) = NaN;
    readings = mooring.internal.radioReadings();
    names = [readings, "poll_failed_share", "no_service_share", "nr5g_share", "ca_secondary_mean"]';
    values = [samples{:, cellstr(readings)}, double(~read), noService, nr5g, samples.ca_secondary_count];
    asMedian = [true(1, numel(readings)), false, false, false, false]';
    worseWhen = [repmat("lower", 1, numel(readings)), "higher", "higher", "lower", "lower"]';
    threshold = [options.RsrpDrop, options.RsrqDrop, options.SinrDrop, options.RssiDrop, ...
        options.RsrpDrop, options.RsrqDrop, options.SinrDrop, ...
        options.FailedRise, options.NoServiceRise, options.Nr5gDrop, options.CarrierDrop]';

    % Each indicator over each window: column 1 the recent one, column
    % k + 1 the one k days before it.
    indicatorCount = numel(names);
    value = nan(indicatorCount, options.Days + 1);
    polls = zeros(indicatorCount, options.Days + 1);
    for index = 1:indicatorCount
        for daysBack = 0:options.Days
            [value(index, daysBack + 1), polls(index, daysBack + 1)] = ...
                windowValue(values(back == daysBack, index), asMedian(index));
        end
    end
    recentValue = value(:, 1);
    recentCount = polls(:, 1);
    earlier = value(:, 2:end);
    earlier(polls(:, 2:end) < options.MinSamples) = NaN;
    baselineDays = sum(~isnan(earlier), 2);
    baselineValue = median(earlier, 2, "omitnan");
    spread = median(abs(earlier - baselineValue), 2, "omitnan");

    change = recentValue - baselineValue;
    worse = change;
    lowerIsWorse = worseWhen == "lower";
    worse(lowerIsWorse) = -worse(lowerIsWorse);
    state = repmat("ok", indicatorCount, 1);
    state(worse >= threshold & worse > options.SpreadFactor * spread) = "degraded";
    state(recentCount < options.MinSamples | baselineDays < options.MinDays) = "insufficient_data";

    indicators = table(names, recentValue, baselineValue, change, threshold, spread, worseWhen, ...
        recentCount, baselineDays, state, 'VariableNames', {'indicator', 'recent', 'baseline', ...
        'change', 'threshold', 'spread', 'worse_when', 'recent_count', 'baseline_days', 'state'});
    if any(state == "degraded")
        verdict = "degraded";
    elseif any(state == "ok")
        verdict = "ok";
    else
        verdict = "insufficient_data";
    end
end

function [value, known] = windowValue(column, asMedian)
% The median or the mean of a window's values that are not NaN, and how
% many they are; NaN without one.
    column = column(~isnan(column));
    known = numel(column);
    if asMedian
        value = median(column);
    else
        value = mean(column);
    end
end
