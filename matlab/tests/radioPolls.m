function samples = radioPolls(folder, at, kind, readings, network, carriers, varargin)
%RADIOPOLLS Made-up polls, as mooring.readRadioSamples reads them.
%   SAMPLES = radioPolls(FOLDER, AT, KIND, READINGS, NETWORK, CARRIERS)
%   writes the polls to a table in FOLDER (writeRadioSamples) and reads it
%   back, so that a test's samples have the types the reader gives.
%
%   SAMPLES = radioPolls(..., CODES) gives each attached poll its
%   network's codes, as writeRadioSamples takes them; without CODES every
%   attached poll is on network 234-30.
%
%   SAMPLES = radioPolls(..., CODES, BANDS) gives each attached poll its
%   band too; without BANDS every attached poll is on band B3.

% SPDX-License-Identifier: GPL-3.0-or-later

    file = fullfile(folder, "polls.csv");
    writeRadioSamples(file, at, kind, readings, network, carriers, varargin{:});
    samples = mooring.readRadioSamples(file);
end
