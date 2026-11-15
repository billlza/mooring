function samples = noRadioSamples(folder)
%NORADIOSAMPLES The samples of a table without rows.

% SPDX-License-Identifier: GPL-3.0-or-later

    file = fullfile(folder, "none.csv");
    layout = mooring.internal.radioFormat("samples");
    writeText(file, layout.header + newline);
    samples = mooring.readRadioSamples(file);
end
