function [names, values] = pollSummary(samples, group, count)
%POLLSUMMARY The counts, shares, means and medians of groups of polls.
%   [NAMES, VALUES] = mooring.internal.pollSummary(SAMPLES, GROUP, COUNT)
%   takes the timetable mooring.readRadioSamples returns and, for each of
%   its polls, the number of the group the poll is in, 1 to COUNT: an hour
%   for mooring.radioHourly, a network for mooring.radioNetworks. NAMES is
%   a string row, and VALUES a cell row with a COUNT by 1 column under
%   each name:
%
%     polls               how many polls the group holds
%     failed              how many of them failed
%     no_service          how many read the M7 without service
%     attached            how many read it attached to a network
%     nr5g_share          the share of the attached polls on 5G (0 to 1)
%     ca_secondary_mean   the mean number of secondary carriers of the
%                         attached polls
%     temperature_c       the median temperature of the polls that read
%     lte_rsrp_dbm, lte_rsrq_db, lte_sinr_db, lte_rssi_dbm,
%     nr_rsrp_dbm, nr_rsrq_db, nr_sinr_db
%                         the median of the polls that hold the reading
%
%   A share, a mean or a median of no poll is NaN.

% SPDX-License-Identifier: GPL-3.0-or-later

    arguments
        samples timetable
        group (:,1) double
        count (1,1) double
    end
    attached = samples.service == "attached";
    attachedCount = groupCount(group, attached, count);
    readings = mooring.internal.radioReadings();
    names = ["polls", "failed", "no_service", "attached", "nr5g_share", ...
        "ca_secondary_mean", "temperature_c", readings];
    values = cell(1, numel(names));
    values{1} = groupCount(group, true(size(group)), count);
    values{2} = groupCount(group, samples.outcome == "failed", count);
    values{3} = groupCount(group, samples.service == "no_service", count);
    values{4} = attachedCount;
    values{5} = groupCount(group, attached & samples.network_service == "nr5g", count) ./ attachedCount;
    values{6} = groupStatistic(group, samples.ca_secondary_count, count, @mean);
    values{7} = groupStatistic(group, samples.temperature_c, count, @median);
    for index = 1:numel(readings)
        values{7 + index} = groupStatistic(group, samples.(readings(index)), count, @median);
    end
end

function total = groupCount(group, flags, count)
% How many of the flagged rows each group holds.
    total = zeros(count, 1);
    if any(flags)
        total = accumarray(group(flags), 1, [count 1]);
    end
end

function result = groupStatistic(group, values, count, statistic)
% The statistic of each group's values that are not NaN; NaN without one.
    result = nan(count, 1);
    known = ~isnan(values);
    if any(known)
        result = accumarray(group(known), values(known), [count 1], statistic, NaN);
    end
end
