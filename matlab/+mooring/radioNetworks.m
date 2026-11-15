function networks = radioNetworks(samples)
%RADIONETWORKS Each network's polls and median readings, side by side.
%   NETWORKS = mooring.radioNetworks(SAMPLES) takes the timetable
%   mooring.readRadioSamples returns and gives a table with a row for each
%   network the M7 was on, in the order of their first polls. After
%   another SIM went into the M7, or where a SIM changes its network, the
%   rows set the networks beside each other. The variables:
%
%     network             the network's codes, as 234-30: the samples'
%                         `plmn`
%     first, last         the times of its first and of its last poll, in
%                         UTC
%     days                how many UTC days hold a poll of it
%     polls               how many polls it holds
%     failed              how many of them failed
%     no_service          how many read the M7 without service
%     attached            how many read it attached
%     nr5g_share          the share of the attached polls on 5G (0 to 1)
%     ca_secondary_mean   the mean number of secondary carriers of the
%                         attached polls
%     temperature_c       the median temperature of the polls that read
%     lte_rsrp_dbm, lte_rsrq_db, lte_sinr_db, lte_rssi_dbm,
%     nr_rsrp_dbm, nr_rsrq_db, nr_sinr_db
%                         the median of the polls that hold the reading
%
%   A poll that holds no network's codes, as a failed poll and a read
%   without service do, counts for the network of the last poll before it
%   that holds them, and a poll before the first such poll for that one's.
%   Samples in which no poll holds a network's codes are one row whose
%   network is missing. SAMPLES without rows give NETWORKS without rows. A
%   share, a mean or a median of no poll is NaN.
%
%   Each network is taken over whatever hours it was polled in. To set the
%   same hours of the day beside each other, pass those polls alone: the
%   evenings from 18:00 UTC are
%
%       mooring.radioNetworks(SAMPLES(hour(SAMPLES.at) >= 18, :))
%
%   The medians say how the radio link read, not how fast it was: the
%   samples hold no throughput.
%
%   See also mooring.readRadioSamples, mooring.radioDegradation,
%   mooring.radioForecast, mooring.radioHourly.

% SPDX-License-Identifier: GPL-3.0-or-later

    arguments
        samples timetable {mooring.internal.mustBeSamples}
    end
    [times, order] = sort(samples.Properties.RowTimes);
    samples = samples(order, :);
    each = mooring.internal.pollNetwork(samples);
    % Samples without a network's codes are one network without a name.
    each(ismissing(each)) = "";
    [network, ~, group] = unique(each, "stable");
    count = numel(network);
    network(network == "") = missing;

    unixTime = posixtime(times);
    first = groupTime(group, unixTime, count, @min);
    last = groupTime(group, unixTime, count, @max);
    dayCount = zeros(count, 1);
    if count > 0
        dayCount = accumarray(group, floor(unixTime / 86400), [count 1], @(day) numel(unique(day)));
    end
    [names, values] = mooring.internal.pollSummary(samples, group, count);
    networks = table(network, first, last, dayCount, values{:}, ...
        'VariableNames', [{'network', 'first', 'last', 'days'}, cellstr(names)]);
end

function at = groupTime(group, unixTime, count, pick)
% The earliest or the latest of each group's times, in UTC.
    picked = zeros(count, 1);
    if count > 0
        picked = accumarray(group, unixTime, [count 1], pick);
    end
    at = datetime(picked, "ConvertFrom", "posixtime", "TimeZone", "UTC");
end
