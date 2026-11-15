function hourly = radioHourly(samples)
%RADIOHOURLY Each hour's polls and median readings.
%   HOURLY = mooring.radioHourly(SAMPLES) takes the timetable
%   mooring.readRadioSamples returns and gives one row for every UTC hour
%   from the first sample's to the last sample's, hours without a sample
%   included, so that the rows are an hour apart. The row times, `hour`,
%   are the hours' starts. The variables:
%
%     polls               how many polls the hour holds
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
%   A share, a mean or a median of no poll is NaN. SAMPLES without rows
%   give HOURLY without rows.
%
%   See also mooring.readRadioSamples, mooring.radioForecast.

% SPDX-License-Identifier: GPL-3.0-or-later

    arguments
        samples timetable {mooring.internal.mustBeSamples}
    end
    hourIndex = floor(posixtime(samples.Properties.RowTimes) / 3600);
    first = 0;
    count = 0;
    if ~isempty(hourIndex)
        first = min(hourIndex);
        count = max(hourIndex) - first + 1;
    end
    bin = hourIndex - first + 1;
    start = datetime((first + (0:count - 1)') * 3600, "ConvertFrom", "posixtime", "TimeZone", "UTC");

    attached = samples.service == "attached";
    attachedCount = binCount(bin, attached, count);
    readings = mooring.internal.radioReadings();
    names = ["polls", "failed", "no_service", "attached", "nr5g_share", ...
        "ca_secondary_mean", "temperature_c", readings];
    values = cell(1, numel(names));
    values{1} = binCount(bin, true(size(bin)), count);
    values{2} = binCount(bin, samples.outcome == "failed", count);
    values{3} = binCount(bin, samples.service == "no_service", count);
    values{4} = attachedCount;
    values{5} = binCount(bin, attached & samples.network_service == "nr5g", count) ./ attachedCount;
    values{6} = binStatistic(bin, samples.ca_secondary_count, count, @mean);
    values{7} = binStatistic(bin, samples.temperature_c, count, @median);
    for index = 1:numel(readings)
        values{7 + index} = binStatistic(bin, samples.(readings(index)), count, @median);
    end
    hourly = timetable(start, values{:}, 'VariableNames', cellstr(names));
    hourly.Properties.DimensionNames{1} = 'hour';
end

function total = binCount(bin, flags, count)
% How many of the flagged rows each bin holds.
    total = zeros(count, 1);
    if any(flags)
        total = accumarray(bin(flags), 1, [count 1]);
    end
end

function result = binStatistic(bin, values, count, statistic)
% The statistic of each bin's values that are not NaN; NaN without one.
    result = nan(count, 1);
    known = ~isnan(values);
    if any(known)
        result = accumarray(bin(known), values(known), [count 1], statistic, NaN);
    end
end
