function [indicators, verdict] = radioDegradation(samples, options)
%RADIODEGRADATION Whether the radio link is worse than its own recent past.
%   [INDICATORS, VERDICT] = mooring.radioDegradation(SAMPLES) compares the
%   last 24 hours of SAMPLES (the timetable mooring.readRadioSamples
%   returns), counted back from the last sample, with the 7 days before
%   them. The baseline holds only the hours of the day the recent window
%   holds, so that a recent window shorter than a day is compared with the
%   same hours of the earlier days and not with their busier or quieter
%   ones.
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
%   and the variables `recent`, `baseline`, `change` (recent less
%   baseline), `threshold`, `worse_when` ("lower" or "higher"),
%   `recent_count`, `baseline_count` (the polls behind each value) and
%   `state`:
%
%     degraded            the value moved the worse way by its threshold
%                         or more
%     ok                  it did not
%     insufficient_data   one of the two windows holds fewer polls with a
%                         value than MinSamples
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
%     Recent         the recent window (default hours(24))
%     Baseline       the baseline before it (default days(7))
%     MinSamples     the fewest polls with a value a window needs
%                    (default 30)
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
%
%   See also mooring.readRadioSamples, mooring.radioForecast.

% SPDX-License-Identifier: GPL-3.0-or-later

    arguments
        samples timetable {mooring.internal.mustBeSamples}
        options.Recent (1,1) duration = hours(24)
        options.Baseline (1,1) duration = days(7)
        options.MinSamples (1,1) double {mustBeInteger, mustBePositive} = 30
        options.RsrpDrop (1,1) double {mustBePositive} = 3
        options.RsrqDrop (1,1) double {mustBePositive} = 2
        options.SinrDrop (1,1) double {mustBePositive} = 3
        options.RssiDrop (1,1) double {mustBePositive} = 3
        options.FailedRise (1,1) double {mustBePositive} = 0.05
        options.NoServiceRise (1,1) double {mustBePositive} = 0.05
        options.Nr5gDrop (1,1) double {mustBePositive} = 0.2
        options.CarrierDrop (1,1) double {mustBePositive} = 0.5
    end
    if options.Recent <= seconds(0) || options.Baseline <= seconds(0)
        error("mooring:radio:BadWindow", "Recent and Baseline are lengths of time above zero.");
    end

    times = samples.Properties.RowTimes;
    recent = false(size(times));
    baseline = false(size(times));
    if ~isempty(times)
        recentStart = max(times) - options.Recent;
        recent = times > recentStart;
        hourOfDay = hour(times);
        baseline = times > recentStart - options.Baseline & times <= recentStart ...
            & ismember(hourOfDay, hourOfDay(recent));
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

    count = numel(names);
    recentValue = nan(count, 1);
    baselineValue = nan(count, 1);
    recentCount = zeros(count, 1);
    baselineCount = zeros(count, 1);
    for index = 1:count
        [recentValue(index), recentCount(index)] = windowValue(values(recent, index), asMedian(index));
        [baselineValue(index), baselineCount(index)] = windowValue(values(baseline, index), asMedian(index));
    end
    change = recentValue - baselineValue;
    worse = change;
    worse(worseWhen == "lower") = -worse(worseWhen == "lower");
    state = repmat("ok", count, 1);
    state(worse >= threshold) = "degraded";
    state(recentCount < options.MinSamples | baselineCount < options.MinSamples) = "insufficient_data";

    indicators = table(names, recentValue, baselineValue, change, threshold, worseWhen, ...
        recentCount, baselineCount, state, 'VariableNames', {'indicator', 'recent', 'baseline', ...
        'change', 'threshold', 'worse_when', 'recent_count', 'baseline_count', 'state'});
    if any(state == "degraded")
        verdict = "degraded";
    elseif any(state == "ok")
        verdict = "ok";
    else
        verdict = "insufficient_data";
    end
end

function [value, count] = windowValue(column, asMedian)
% The median or the mean of a window's values that are not NaN, and how
% many they are; NaN without one.
    known = column(~isnan(column));
    count = numel(known);
    if asMedian
        value = median(known);
    else
        value = mean(known);
    end
end
