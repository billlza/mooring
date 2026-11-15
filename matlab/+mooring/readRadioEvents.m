function events = readRadioEvents(file)
%READRADIOEVENTS The radio events of a table mooringctl printed.
%   EVENTS = mooring.readRadioEvents(FILE) reads the file that
%
%       mooringctl router history --csv events > FILE
%
%   wrote: one row per change between two polls of the M7. EVENTS is a
%   timetable whose row times, `at`, are the Mac's times of the polls that
%   showed the changes, in UTC. Its variables are categorical, and
%   undefined where an event holds no value:
%
%     event    poll_failed | poll_recovered | router_rebooted |
%              service_lost | service_regained | network_service_changed |
%              data_service_changed | band_changed | plmn_changed |
%              session_restarted
%     reason   why a failed poll failed
%     from     what a change went from: a service type, a band (B3, n78)
%              or a network's codes (234-30)
%     to       what it went to
%
%   The file is read as strictly as mooring.readRadioSamples reads its
%   file.
%
%   See also mooring.readRadioSamples, mooring.radioHistory.

% SPDX-License-Identifier: GPL-3.0-or-later

    arguments
        file (1,1) string
    end
    layout = mooring.internal.radioFormat("events");
    events = mooring.internal.asTimetable(mooring.internal.readCsv(file, layout), layout);
end
