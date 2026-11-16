function fig = plotRadio(samples, options)
%PLOTRADIO The radio history at a glance.
%   FIG = mooring.plotRadio(SAMPLES) draws the timetable
%   mooring.readRadioSamples returns in a new figure, over one time axis
%   in UTC:
%
%     Signal               LTE RSRP, NR RSRP and LTE RSSI, in dBm
%     Quality              LTE and NR RSRQ and SINR, in dB
%     Band                 the primary carrier's band at each poll
%     Secondary carriers   how many were aggregated
%     Service              each poll as failed, without service, on LTE
%                          or on 5G
%
%   and returns the figure. The panels zoom and pan together.
%
%   FIG = mooring.plotRadio(SAMPLES, Events=EVENTS) adds a panel with the
%   changes between polls, from the timetable mooring.readRadioEvents
%   returns.
%
%   A panel of names (the bands, the services, the changes) is as tall as
%   its names need, a name being spelled as the table spells it. The
%   panels share the time axis, and the last one alone names its times.
%   Where names still lie over one another, the window is too low for
%   them: make it taller.
%
%   FIG = mooring.plotRadio(..., Visible="off") draws without showing the
%   figure, for a script that saves it (exportgraphics).
%
%   SAMPLES without rows are refused: mooring:radio:NothingToPlot.
%
%   See also mooring.readRadioSamples, mooring.readRadioEvents.

% SPDX-License-Identifier: GPL-3.0-or-later

    arguments
        samples timetable {mooring.internal.mustBeSamples}
        options.Events timetable
        options.Visible (1,1) matlab.lang.OnOffSwitchState = "on"
    end
    if isempty(samples)
        error("mooring:radio:NothingToPlot", "There are no samples to plot.");
    end
    withEvents = isfield(options, "Events");
    if withEvents && ~ismember("event", options.Events.Properties.VariableNames)
        error("mooring:radio:NotEvents", "The Events timetable is not one of radio events: it has no event.");
    end

    at = samples.Properties.RowTimes;
    span = [min(at), max(at)];
    % Each poll's service: failed, without service, or the network
    % service type it was attached with.
    state = strings(height(samples), 1);
    state(samples.outcome == "failed") = "poll failed";
    state(samples.service == "no_service") = "no service";
    attached = samples.service == "attached";
    state(attached) = string(samples.network_service(attached));
    states = categorical(state);

    % The rows of the layout each panel takes: three for lines, two for
    % the carriers' steps, what its names need for a panel of names, and
    % two more for the last panel, under which the times are named.
    rows = [3, 3, nameRows(samples.band), 2, nameRows(states)];
    if withEvents
        rows(end + 1) = nameRows(options.Events.event);
    end
    rows(end) = rows(end) + 2;

    fig = figure("Visible", options.Visible, "Name", "Mooring radio history");
    tiles = tiledlayout(fig, sum(rows), 1, "TileSpacing", "compact");
    title(tiles, "Radio history, " + string(span(1), "yyyy-MM-dd HH:mm") + " to " ...
        + string(span(2), "yyyy-MM-dd HH:mm") + " UTC");

    signal = nexttile(tiles, [rows(1), 1]);
    plot(signal, at, samples.lte_rsrp_dbm, at, samples.nr_rsrp_dbm, at, samples.lte_rssi_dbm);
    ylabel(signal, "dBm");
    legend(signal, "LTE RSRP", "NR RSRP", "LTE RSSI", "Location", "eastoutside");
    title(signal, "Signal");

    quality = nexttile(tiles, [rows(2), 1]);
    plot(quality, at, samples.lte_rsrq_db, at, samples.nr_rsrq_db, ...
        at, samples.lte_sinr_db, at, samples.nr_sinr_db);
    ylabel(quality, "dB");
    legend(quality, "LTE RSRQ", "NR RSRQ", "LTE SINR", "NR SINR", "Location", "eastoutside");
    title(quality, "Quality");

    band = nexttile(tiles, [rows(3), 1]);
    marks(band, at, samples.band, span);
    title(band, "Band of the primary carrier");

    carriers = nexttile(tiles, [rows(4), 1]);
    stairs(carriers, at, samples.ca_secondary_count);
    title(carriers, "Secondary carriers");

    service = nexttile(tiles, [rows(5), 1]);
    marks(service, at, states, span);
    title(service, "Service");

    panels = [signal, quality, band, carriers, service];
    if withEvents
        changes = nexttile(tiles, [rows(6), 1]);
        marks(changes, options.Events.Properties.RowTimes, options.Events.event, span);
        title(changes, "Changes between polls");
        panels = [panels, changes];
    end
    linkaxes(panels, "x");
    % One time axis: the times are named once, under the last panel. The
    % panels above it keep their ticks and lose the ticks' labels and the
    % label of the year beside them.
    for upper = panels(1:end - 1)
        xticklabels(upper, {});
        upper.XAxis.SecondaryLabelFormat = "";
    end
end

function rows = nameRows(names)
% The rows of the layout a panel of names takes: one, and one more for
% every two names it shows; two at least.
    shown = numel(unique(names(~isundefined(names))));
    rows = max(2, 1 + ceil(shown / 2));
end

function marks(target, times, names, span)
% A dot at each time, at the height of its name; times without a name
% have none.
    named = ~isundefined(names);
    if any(named)
        plot(target, times(named), removecats(names(named)), ".");
    else
        % Nothing to mark: an empty panel over the samples' span, so that
        % it has the others' time axis.
        plot(target, span, [NaN, NaN]);
    end
    % A name is shown as it is spelled: its underscore lowers no letter.
    target.TickLabelInterpreter = "none";
end
