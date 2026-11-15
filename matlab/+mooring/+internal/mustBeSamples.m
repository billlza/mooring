function mustBeSamples(samples)
%MUSTBESAMPLES Refuse a timetable that is not one of radio samples.
%   mooring.internal.mustBeSamples(SAMPLES) throws mooring:radio:NotSamples
%   unless SAMPLES has every variable mooring.readRadioSamples returns.

% SPDX-License-Identifier: GPL-3.0-or-later

    layout = mooring.internal.radioFormat("samples");
    absent = setdiff(layout.names(3:end), string(samples.Properties.VariableNames));
    if ~isempty(absent)
        error("mooring:radio:NotSamples", ...
            "The timetable is not one of radio samples: it has no %s.", join(absent, ", "));
    end
end
