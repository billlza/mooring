function q = quantiles(values, p)
%QUANTILES Quantiles of the values that are not NaN, by linear interpolation.
%   Q = mooring.internal.quantiles(VALUES, P) returns, for each
%   probability in P (0 to 1), the quantile of the non-NaN VALUES: with
%   the N values in order, the one at position 1 + (N - 1) * P,
%   interpolated between its two neighbours. Q has the size of P and is
%   NaN when VALUES holds no number. It needs no toolbox.

% SPDX-License-Identifier: GPL-3.0-or-later

    arguments
        values double
        p double {mustBeNonnegative, mustBeLessThanOrEqual(p, 1)}
    end
    sorted = sort(values(~isnan(values)));
    sorted = sorted(:);
    q = nan(size(p));
    count = numel(sorted);
    if count == 0
        return
    end
    position = 1 + (count - 1) * p(:);
    below = floor(position);
    above = ceil(position);
    q(:) = sorted(below) + (position - below) .* (sorted(above) - sorted(below));
end
