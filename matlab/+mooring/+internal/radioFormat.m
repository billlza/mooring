function layout = radioFormat(name)
%RADIOFORMAT The header, row pattern and column types of a radio table.
%   LAYOUT = mooring.internal.radioFormat(NAME) describes the table that
%   `mooringctl router history --csv NAME` prints, NAME being "samples" or
%   "events" (docs/design.md section 15.6, rule 13):
%
%     names     the columns' names, in order;
%     types     per column, "f" for a number and "s" for a name;
%     header    the table's first line, which is the format's version: a
%               file with another first line is not read;
%     pattern   the regular expression every other line matches whole.

% SPDX-License-Identifier: GPL-3.0-or-later

    arguments
        name (1,1) string {mustBeMember(name, ["samples", "events"])}
    end
    % The Mac's time twice: seconds since 1970 (twelve digits reach past
    % the year 9999) and the same instant as a UTC stamp.
    time = "\d{1,12},\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z";
    if name == "samples"
        layout.names = [ ...
            "at_unix", "at_utc", "outcome", "failure", "uptime_secs", ...
            "temperature_c", "thermal", "service", "network_service", ...
            "data_service", "band", "ca_secondary_count", ...
            "lte_rsrp_dbm", "lte_rsrq_db", "lte_sinr_db", "lte_rssi_dbm", ...
            "nr_rsrp_dbm", "nr_rsrq_db", "nr_sinr_db", "plmn", "session_secs"];
        layout.types = [ ...
            "f", "s", "s", "s", "f", "f", "s", "s", "s", "s", "s", "f", ...
            "f", "f", "f", "f", "f", "f", "f", "s", "f"];
        layout.pattern = time ...
            + ",(read|failed),[a-z_]*,\d*,-?\d*,[a-z0-9_]*,[a-z_]*" ...
            + ",[a-z0-9_]*,[a-z0-9_]*,([Bn]\d+)?,\d*" ...
            + "(,(-?\d+\.\d)?){7}" ...
            + ",(\d{3}-\d{2,3})?,\d*";
    else
        layout.names = ["at_unix", "at_utc", "event", "reason", "from", "to"];
        layout.types = ["f", "s", "s", "s", "s", "s"];
        layout.pattern = time + ",[a-z_]+,[a-z_]*,[A-Za-z0-9_-]*,[A-Za-z0-9_-]*";
    end
    layout.header = join(layout.names, ",");
end
