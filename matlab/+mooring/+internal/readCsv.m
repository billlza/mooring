function columns = readCsv(file, layout)
%READCSV The columns of a table mooringctl printed, read strictly.
%   COLUMNS = mooring.internal.readCsv(FILE, LAYOUT) reads FILE as the
%   table LAYOUT describes (mooring.internal.radioFormat) and returns its
%   columns in a cell row: a double column for a number, with NaN for an
%   empty cell, and a string column for a name, with "" for an empty cell.
%
%   Nothing is guessed. The file is refused when it is missing
%   (mooring:radio:NoFile), does not end with a line end, as a file cut
%   short does not (mooring:radio:Incomplete), begins with another line
%   than the header (mooring:radio:UnknownHeader), holds a line that is
%   not a row of the table (mooring:radio:BadRow), or gives a row two
%   different times (mooring:radio:TimeMismatch). CR LF line ends are read
%   as line ends.

% SPDX-License-Identifier: GPL-3.0-or-later

    arguments
        file (1,1) string
        layout (1,1) struct
    end
    if ~isfile(file)
        error("mooring:radio:NoFile", "There is no file %s.", file);
    end
    text = strrep(fileread(file), [char(13) newline], newline);
    if isempty(text) || text(end) ~= newline
        error("mooring:radio:Incomplete", ...
            "%s does not end with a line end, so its last line may be cut short.", file);
    end
    lines = split(string(text(1:end - 1)), newline);
    if lines(1) ~= layout.header
        % The line is shown as far as the header reaches and 80 characters
        % more: a header with columns added is seen with them, and a line
        % that is no header at all is not shown whole.
        found = lines(1);
        shown = strlength(layout.header) + 80;
        if strlength(found) > shown
            found = extractBefore(found, shown + 1) + "...";
        end
        error("mooring:radio:UnknownHeader", ...
            "The first line of %s is not the header this package reads.\n  found:    %s\n  expected: %s", ...
            file, found, layout.header);
    end
    rows = numel(lines) - 1;
    columns = cell(1, numel(layout.types));
    numeric = layout.types == "f";
    if rows == 0
        columns(numeric) = {zeros(0, 1)};
        columns(~numeric) = {strings(0, 1)};
        return
    end
    lines = lines(2:end);
    starts = regexp(cellstr(lines), char("^" + layout.pattern + "$"), "once");
    bad = find(cellfun(@isempty, starts), 1);
    if ~isempty(bad)
        error("mooring:radio:BadRow", ...
            "Line %d of %s is not a row of this table.", bad + 1, file);
    end
    % Every line has the header's number of commas, so the cells form a
    % matrix; a single line's cells come as a column and are laid as a row.
    cells = reshape(split(lines, ","), rows, []);
    for index = 1:numel(columns)
        if numeric(index)
            columns{index} = str2double(cells(:, index));
        else
            columns{index} = cells(:, index);
        end
    end
    % Each row names its time twice, as seconds and as a UTC stamp. The
    % two must agree, or the columns are not the ones the header names.
    at = datetime(columns{1}, "ConvertFrom", "posixtime", "TimeZone", "UTC");
    differs = find(string(at, "yyyy-MM-dd'T'HH:mm:ss'Z'") ~= columns{2}, 1);
    if ~isempty(differs)
        error("mooring:radio:TimeMismatch", ...
            "Line %d of %s gives %s seconds and %s, which are not the same time.", ...
            differs + 1, file, cells(differs, 1), cells(differs, 2));
    end
end
