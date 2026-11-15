function samples = radioPolls(folder, at, kind, readings, network, carriers)
%RADIOPOLLS Made-up polls, as mooring.readRadioSamples reads them.
%   SAMPLES = radioPolls(FOLDER, AT, KIND, READINGS, NETWORK, CARRIERS)
%   writes the polls to a table in FOLDER (writeRadioSamples) and reads it
%   back, so that a test's samples have the types the reader gives.

% SPDX-License-Identifier: GPL-3.0-or-later

    file = fullfile(folder, "polls.csv");
    writeRadioSamples(file, at, kind, readings, network, carriers);
    samples = mooring.readRadioSamples(file);
end
