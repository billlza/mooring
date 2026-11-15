function network = pollNetwork(samples)
%POLLNETWORK The network each poll was on.
%   NETWORK = mooring.internal.pollNetwork(SAMPLES) takes the timetable
%   mooring.readRadioSamples returns and gives a string column with a row
%   per poll: the network's codes, as 234-30. A poll that holds none, as a
%   failed poll and a read without service do, has the codes of the last
%   poll before it that holds them, and a poll before the first that holds
%   them has that one's: a poll that could not tell its network was most
%   likely on the one the M7 was on before it. When no poll holds a
%   network's codes every row is a missing string.

% SPDX-License-Identifier: GPL-3.0-or-later

    arguments
        samples timetable
    end
    network = repmat(string(missing), height(samples), 1);
    [~, order] = sort(samples.Properties.RowTimes);
    codes = samples.plmn(order);
    holds = ~ismissing(codes);
    if any(holds)
        % In the order of time, each poll takes the codes of the last
        % holder at or before it; the polls before the first holder take
        % the first holder's.
        held = string(codes(holds));
        network(order) = held(max(cumsum(holds), 1));
    end
end
