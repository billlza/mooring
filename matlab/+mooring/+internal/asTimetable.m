function result = asTimetable(columns, layout)
%ASTIMETABLE A table's columns as a timetable.
%   RESULT = mooring.internal.asTimetable(COLUMNS, LAYOUT) takes the
%   columns mooring.internal.readCsv returned for LAYOUT and returns a
%   timetable whose row times, named `at`, are the rows' times in UTC, and
%   whose variables are the columns after the two times, under the
%   header's names: a number as a double (NaN for an empty cell), a name
%   as a categorical (undefined for an empty cell).

% SPDX-License-Identifier: GPL-3.0-or-later

    arguments
        columns (1,:) cell
        layout (1,1) struct
    end
    at = datetime(columns{1}, "ConvertFrom", "posixtime", "TimeZone", "UTC");
    values = columns(3:end);
    for index = find(layout.types(3:end) == "s")
        values{index} = categorical(values{index});
    end
    result = timetable(at, values{:}, 'VariableNames', cellstr(layout.names(3:end)));
    result.Properties.DimensionNames{1} = 'at';
end
