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
    fig = figure("Visible", options.Visible, "Name", "Mooring radio history");
    tiles = tiledlayout(fig, 5 + withEvents, 1, "TileSpacing", "compact");
    title(tiles, "Radio history, " + string(span(1), "yyyy-MM-dd HH:mm") + " to " ...
        + string(span(2), "yyyy-MM-dd HH:mm") + " UTC");

    signal = nexttile(tiles);
    plot(signal, at, samples.lte_rsrp_dbm, at, samples.nr_rsrp_dbm, at, samples.lte_rssi_dbm);
    ylabel(signal, "dBm");
    legend(signal, "LTE RSRP", "NR RSRP", "LTE RSSI", "Location", "eastoutside");
    title(signal, "Signal");

    quality = nexttile(tiles);
    plot(quality, at, samples.lte_rsrq_db, at, samples.nr_rsrq_db, ...
        at, samples.lte_sinr_db, at, samples.nr_sinr_db);
    ylabel(quality, "dB");
    legend(quality, "LTE RSRQ", "NR RSRQ", "LTE SINR", "NR SINR", "Location", "eastoutside");
    title(quality, "Quality");

    band = nexttile(tiles);
    marks(band, at, samples.band, span);
    title(band, "Band of the primary carrier");

    carriers = nexttile(tiles);
    stairs(carriers, at, samples.ca_secondary_count);
    title(carriers, "Secondary carriers");

    % Each poll's service: failed, without service, or the network
    % service type it was attached with.
    state = strings(height(samples), 1);
    state(samples.outcome == "failed") = "poll failed";
    state(samples.service == "no_service") = "no service";
    attached = samples.service == "attached";
    state(attached) = string(samples.network_service(attached));
    service = nexttile(tiles);
    marks(service, at, categorical(state), span);
    title(service, "Service");

    panels = [signal, quality, band, carriers, service];
    if withEvents
        changes = nexttile(tiles);
        marks(changes, options.Events.Properties.RowTimes, options.Events.event, span);
        title(changes, "Changes between polls");
        panels = [panels, changes];
    end
    linkaxes(panels, "x");
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
end
