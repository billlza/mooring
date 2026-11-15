function file = fixtureFile(name)
%FIXTUREFILE A golden table of contract/history-fixtures.
%   The two tables there are the ones the Rust tests pin byte for byte to
%   what `mooringctl router history --csv` prints, so that a test reading
%   them here reads what the command writes.

% SPDX-License-Identifier: GPL-3.0-or-later

    root = fileparts(fileparts(fileparts(mfilename("fullpath"))));
    file = string(fullfile(root, "contract", "history-fixtures", name));
end
