function writeRadioSamples(file, at, kind, readings, network, carriers, codes, bands)
%WRITERADIOSAMPLES A samples table of made-up polls, as mooringctl prints one.
%   writeRadioSamples(FILE, AT, KIND, READINGS, NETWORK, CARRIERS) writes
%   one row per poll, for N polls:
%
%     AT        N by 1, seconds since 1970
%     KIND      N by 1 strings: "attached", "no_service" or "failed"
%     READINGS  N by 7 doubles in the table's order (LTE RSRP, RSRQ, SINR,
%               RSSI, NR RSRP, RSRQ, SINR), with at most one decimal; NaN
%               for a reading not reported
%     NETWORK   N by 1 strings: "nr5g" or "lte"
%     CARRIERS  N by 1 counts of secondary carriers
%
%   READINGS, NETWORK and CARRIERS count for the attached polls only.
%   Every read has an uptime of 1000 s and 44 degrees; every attached poll
%   is on band B3 of network 234-30 with a session of 600 s.
%
%   writeRadioSamples(..., CODES) gives each attached poll its network's
%   codes: N by 1 strings, as "234-20", or "" for a poll that reports
%   none.
%
%   writeRadioSamples(..., CODES, BANDS) gives each attached poll its
%   band too: N by 1 strings, as "n78".

% SPDX-License-Identifier: GPL-3.0-or-later

    arguments
        file (1,1) string
        at (:,1) double
        kind (:,1) string
        readings (:,7) double
        network (:,1) string
        carriers (:,1) double
        codes (:,1) string = repmat("234-30", numel(at), 1)
        bands (:,1) string = repmat("B3", numel(at), 1)
    end
    stamp = string(datetime(at, "ConvertFrom", "posixtime", "TimeZone", "UTC"), ...
        "yyyy-MM-dd'T'HH:mm:ss'Z'");
    time = compose("%d", at) + "," + stamp;
    cells = compose("%.1f", readings);
    cells(isnan(readings)) = "";
    data = repmat("lte_plus", numel(at), 1);
    data(network == "nr5g") = "nr_sub6";

    rows = time + ",failed,unreachable" + string(repmat(',', 1, 17));
    idle = kind == "no_service";
    rows(idle) = time(idle) + ",read,,1000,44,normal,no_service" + string(repmat(',', 1, 13));
    on = kind == "attached";
    if any(on)
        rows(on) = time(on) + ",read,,1000,44,normal,attached," + network(on) + "," + data(on) ...
            + "," + bands(on) + "," + compose("%d", carriers(on)) + "," + join(cells(on, :), ",", 2) ...
            + "," + codes(on) + ",600";
    end

    layout = mooring.internal.radioFormat("samples");
    writeText(file, join([layout.header; rows], newline) + newline);
end
