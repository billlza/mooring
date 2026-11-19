function [kept, code] = onNetwork(samples, network)
%ONNETWORK The polls of the network asked for.
%   [KEPT, CODE] = mooring.internal.onNetwork(SAMPLES, NETWORK) takes the
%   timetable mooring.readRadioSamples returns and what the Network
%   argument of mooring.radioDegradation and mooring.radioForecast names:
%
%     "last"   the network of the last poll;
%     "all"    every poll, whatever its network;
%     codes    a network's codes, as "234-30".
%
%   KEPT is a logical column, true for the polls of that network
%   (mooring.internal.pollNetwork says which network a poll is of), and
%   CODE the network's codes. With "all", and with "last" where no poll
%   holds a network's codes, every poll is kept and CODE is a missing
%   string. Codes no poll is on are refused: mooring:radio:UnknownNetwork.

% SPDX-License-Identifier: GPL-3.0-or-later

    arguments
        samples timetable
        network (1,1) string
    end
    kept = true(height(samples), 1);
    code = string(missing);
    if network == "all"
        return
    end
    each = mooring.internal.pollNetwork(samples);
    known = unique(each(~ismissing(each)));
    if network == "last"
        if isempty(known)
            return
        end
        % Polls can share a second. Within that second keep their row
        % order, as pollNetwork does when attributing a poll without codes.
        times = samples.Properties.RowTimes;
        latest = find(times == max(times), 1, "last");
        code = each(latest);
    elseif ismember(network, known)
        code = network;
    else
        held = "no poll of the samples holds a network's codes";
        if ~isempty(known)
            held = "the samples' networks are " + join(known, ", ");
        end
        error("mooring:radio:UnknownNetwork", ...
            "No poll is on network %s: %s. Network is ""last"", ""all"" or a network's codes, as ""234-30"".", ...
            network, held);
    end
    kept = each == code;
end
