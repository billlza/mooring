function slope = seasonalSlope(offset, values)
%SEASONALSLOPE The slope of hourly values that follow a daily pattern, robustly.
%   SLOPE = mooring.internal.seasonalSlope(OFFSET, VALUES) is the median
%   of the slopes between every two of VALUES that are of the same hour of
%   the day (the seasonal form of the Theil-Sen estimator): the daily
%   pattern cancels in each pair, and a few hours far from the others do
%   not move a median. OFFSET is each value's hour as a whole number of
%   hours from a common origin, in increasing order; VALUES holds no NaN.
%   Both are columns of one length. SLOPE is per hour, and NaN when no two
%   values are a whole number of days apart.

% SPDX-License-Identifier: GPL-3.0-or-later

    arguments
        offset (:,1) double
        values (:,1) double
    end
    count = numel(offset);
    [earlier, later] = find(triu(true(count, count), 1));
    apart = offset(later) - offset(earlier);
    sameHour = mod(apart, 24) == 0;
    slope = median((values(later(sameHour)) - values(earlier(sameHour))) ./ apart(sameHour));
end
