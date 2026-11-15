function names = radioReadings()
%RADIOREADINGS The names of the samples' signal readings, in the table's order.
%   NAMES = mooring.internal.radioReadings() is a string row: LTE RSRP,
%   RSRQ, SINR and RSSI, then NR RSRP, RSRQ and SINR, each under its
%   column's name. Powers are in dBm, ratios in dB.

% SPDX-License-Identifier: GPL-3.0-or-later

    names = [ ...
        "lte_rsrp_dbm", "lte_rsrq_db", "lte_sinr_db", "lte_rssi_dbm", ...
        "nr_rsrp_dbm", "nr_rsrq_db", "nr_sinr_db"];
end
