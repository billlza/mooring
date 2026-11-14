function writeText(file, text)
%WRITETEXT Write TEXT to FILE, byte for byte.

% SPDX-License-Identifier: GPL-3.0-or-later

    handle = fopen(file, "w");
    assert(handle ~= -1, "mooring:test:CannotWrite", "Cannot write %s.", file);
    fprintf(handle, "%s", text);
    fclose(handle);
end
