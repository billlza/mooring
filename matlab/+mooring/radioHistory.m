function [samples, events] = radioHistory(options)
%RADIOHISTORY The radio history, read from mooringctl on this Mac.
%   [SAMPLES, EVENTS] = mooring.radioHistory() runs, on the Mac Mooring
%   runs on,
%
%       mooringctl router history --csv samples
%       mooringctl router history --csv events
%
%   and returns what mooring.readRadioSamples and mooring.readRadioEvents
%   read from the two tables: yesterday and today, UTC. The command reads
%   the history's files and changes nothing; the daemon need not run. The
%   two tables are two readings: a poll between them gives the second one
%   more.
%
%   On another machine there is no mooringctl to run. Send the tables
%   there from the Mac (docs/runbooks/radio-analysis.md) and read them
%   with mooring.readRadioSamples and mooring.readRadioEvents.
%
%   Name-value arguments:
%     Days        the last so many UTC days, today among them (1 to 90);
%                 not together with Since or Until
%     Since       the first UTC day, as "2026-11-01"
%     Until       the last UTC day, as "2026-11-14"; a range holds at
%                 most 90 days
%     Mooringctl  the program (default
%                 ~/Applications/Mooring.app/Contents/MacOS/mooringctl)
%
%   Errors: mooring:radio:NoMooringctl when the program is not there,
%   mooring:radio:BadDay for a day in another form,
%   mooring:radio:DaysAndRange, and mooring:radio:CommandFailed, with
%   what the command said, when it does not end with status 0.
%
%   See also mooring.readRadioSamples, mooring.readRadioEvents.

% SPDX-License-Identifier: GPL-3.0-or-later

    arguments
        options.Days (1,1) double {mustBeInteger, mustBePositive, mustBeLessThanOrEqual(options.Days, 90)}
        options.Since (1,1) string = ""
        options.Until (1,1) string = ""
        options.Mooringctl (1,1) string = fullfile(getenv("HOME"), "Applications", ...
            "Mooring.app", "Contents", "MacOS", "mooringctl")
    end
    since = options.Since;
    if isfield(options, "Days")
        if since ~= "" || options.Until ~= ""
            error("mooring:radio:DaysAndRange", ...
                "Days counts back from today, so it does not go with Since or Until.");
        end
        since = string(datetime("now", "TimeZone", "UTC") - days(options.Days - 1), "uuuu-MM-dd");
    end
    range = dayOption("--since", since) + dayOption("--until", options.Until);
    if ~isfile(options.Mooringctl)
        error("mooring:radio:NoMooringctl", ...
            "There is no mooringctl at %s. Name it with Mooringctl, or read tables sent from the Mac with mooring.readRadioSamples.", ...
            options.Mooringctl);
    end
    folder = string(tempname);
    mkdir(folder);
    try
        samples = mooring.readRadioSamples(exported(options.Mooringctl, range, "samples", folder));
        events = mooring.readRadioEvents(exported(options.Mooringctl, range, "events", folder));
    catch failure
        rmdir(folder, "s");
        rethrow(failure);
    end
    rmdir(folder, "s");
end

function text = dayOption(flag, day)
% The command's option for a day, or nothing for no day. Only a day in
% the command's own form goes into the command line.
    text = "";
    if day == ""
        return
    end
    if ~strcmp(regexp(char(day), '^\d{4}-\d{2}-\d{2}$', 'match', 'once'), day)
        error("mooring:radio:BadDay", "%s is not a day as 2026-11-14.", day);
    end
    text = " " + flag + " " + day;
end

function file = exported(program, range, name, folder)
% The file one table was written to. The table goes to the file, and
% what the command says besides (its errors) comes back as `said`.
    file = fullfile(folder, "radio-" + name + ".csv");
    command = quoted(program) + " router history" + range + " --csv " + name ...
        + " 2>&1 > " + quoted(file);
    [status, said] = system(command);
    if status ~= 0
        error("mooring:radio:CommandFailed", ...
            "mooringctl router history failed with status %d:\n%s", status, strtrim(said));
    end
end

function text = quoted(text)
% One word for the shell, whatever the text holds.
    text = "'" + replace(text, "'", "'\''") + "'";
end
