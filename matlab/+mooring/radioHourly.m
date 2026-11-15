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
%   give HOURLY without rows. An hour holds its polls whatever network
%   they were on; mooring.radioNetworks gives the same of each network.
%
%   See also mooring.readRadioSamples, mooring.radioForecast,
%   mooring.radioNetworks.

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
    start = datetime((first + (0:count - 1)') * 3600, "ConvertFrom", "posixtime", "TimeZone", "UTC");

    [names, values] = mooring.internal.pollSummary(samples, hourIndex - first + 1, count);
    hourly = timetable(start, values{:}, 'VariableNames', cellstr(names));
    hourly.Properties.DimensionNames{1} = 'hour';
end
