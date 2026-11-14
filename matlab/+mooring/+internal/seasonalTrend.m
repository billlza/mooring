function [slope, profile] = seasonalTrend(offset, hourOfDay, values)
%SEASONALTREND A trend and a profile over the hours of the day, robustly.
%   [SLOPE, PROFILE] = mooring.internal.seasonalTrend(OFFSET, HOUROFDAY,
%   VALUES) fits VALUES, one per hour, as
%
%       SLOPE * OFFSET + PROFILE(HOUROFDAY + 1)
%
%   OFFSET is each value's hour as a whole number of hours from a common
%   origin, in increasing order; HOUROFDAY is its hour of the day, 0 to
%   23; VALUES holds no NaN. All three are columns of one length.
%
%   SLOPE, per hour, is the median of the slopes between every two values
%   of the same hour of the day (the seasonal form of the Theil-Sen
%   estimator): the daily pattern cancels in each pair, and a few hours
%   far from the others do not move a median. It is NaN when no two values
%   share an hour of the day. PROFILE, 24 by 1, is for each hour of the
%   day the median of what the values of that hour are once the trend is
%   taken out, at the origin; NaN for an hour of the day without a value.

% SPDX-License-Identifier: GPL-3.0-or-later

    arguments
        offset (:,1) double
        hourOfDay (:,1) double
        values (:,1) double
    end
    [earlier, later] = find(triu(true(numel(offset)), 1));
    apart = offset(later) - offset(earlier);
    sameHour = mod(apart, 24) == 0;
    slope = median((values(later(sameHour)) - values(earlier(sameHour))) ./ apart(sameHour));
    profile = accumarray(hourOfDay + 1, values - slope * offset, [24 1], @median, NaN);
end
