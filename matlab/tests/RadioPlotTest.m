classdef RadioPlotTest < matlab.unittest.TestCase
%RADIOPLOTTEST The history drawn, without showing the figure.

% SPDX-License-Identifier: GPL-3.0-or-later

    properties
        Folder (1,1) string
    end

    methods (TestMethodSetup)
        function makeFolder(testCase)
            fixture = testCase.applyFixture(matlab.unittest.fixtures.TemporaryFolderFixture);
            testCase.Folder = fixture.Folder;
        end
    end

    methods
        function [names, found] = panels(testCase, fig)
            % The panels and their titles, from the top one down; the
            % figure is closed when the test ends.
            testCase.addTeardown(@close, fig);
            found = findobj(fig, "Type", "axes");
            tile = zeros(numel(found), 1);
            names = strings(numel(found), 1);
            for index = 1:numel(found)
                tile(index) = found(index).Layout.Tile;
                names(index) = found(index).Title.String;
            end
            [~, order] = sort(tile);
            names = names(order);
            found = found(order);
        end

        function rows = layoutRows(testCase, found)
            % The rows of the layout each of a figure's panels takes, from
            % the top one down: the panels are one under another in the
            % layout's one column, and leave no row of it empty.
            spans = zeros(numel(found), 2);
            first = zeros(numel(found), 1);
            for index = 1:numel(found)
                spans(index, :) = found(index).Layout.TileSpan;
                first(index) = found(index).Layout.Tile;
            end
            rows = spans(:, 1);
            testCase.verifyEqual(spans(:, 2), ones(numel(found), 1));
            testCase.verifyEqual(first, 1 + [0; cumsum(rows(1:end - 1))]);
            testCase.verifyEqual(found(1).Parent.GridSize, [sum(rows), 1]);
        end

        function verifyOnlyTheLastNamesItsTimes(testCase, found)
            % The panels above the last one show neither a time at a tick
            % nor the year beside the ticks: their labels are set, to
            % nothing. The last one's are MATLAB's own.
            for index = 1:numel(found) - 1
                testCase.verifyEqual(string(found(index).XTickLabelMode), "manual");
                testCase.verifyTrue(all(strlength(string(found(index).XTickLabel)) == 0, "all"));
                testCase.verifyEqual(string(found(index).XAxis.SecondaryLabelFormatMode), "manual");
                testCase.verifyEqual(string(found(index).XAxis.SecondaryLabelFormat), "");
            end
            testCase.verifyEqual(string(found(end).XTickLabelMode), "auto");
            testCase.verifyEqual(string(found(end).XAxis.SecondaryLabelFormatMode), "auto");
        end
    end

    methods (Test)
        function theSamplesAreDrawnInFivePanelsOverOneTimeAxis(testCase)
            samples = mooring.readRadioSamples(fixtureFile("radio-samples.csv"));
            fig = mooring.plotRadio(samples, Visible="off");

            [names, found] = testCase.panels(fig);
            testCase.verifyEqual(names, ["Signal"; "Quality"; ...
                "Band of the primary carrier"; "Secondary carriers"; "Service"]);
            testCase.verifyEqual(string(fig.Visible), "off");
            testCase.verifyEqual(string(fig.Name), "Mooring radio history");
            % Three lines of signal and four of quality; a zoom of one
            % panel is a zoom of all.
            testCase.verifyNumElements(findobj(found(1), "Type", "line"), 3);
            testCase.verifyNumElements(findobj(found(2), "Type", "line"), 4);
            found(1).XLim = [samples.at(2), samples.at(5)];
            testCase.verifyEqual(posixtime(found(5).XLim), posixtime([samples.at(2), samples.at(5)]));
        end

        function theEventsAreASixthPanel(testCase)
            samples = mooring.readRadioSamples(fixtureFile("radio-samples.csv"));
            events = mooring.readRadioEvents(fixtureFile("radio-events.csv"));
            fig = mooring.plotRadio(samples, Events=events, Visible="off");
            testCase.verifyEqual(testCase.panels(fig), ["Signal"; "Quality"; ...
                "Band of the primary carrier"; "Secondary carriers"; "Service"; "Changes between polls"]);

            % Events without a row are a panel without a mark.
            fig = mooring.plotRadio(samples, Events=events([], :), Visible="off");
            testCase.verifyNumElements(testCase.panels(fig), 6);
        end

        function aHistoryThatNeverAttachedIsDrawnToo(testCase)
            at = 1791918000 + [0; 60; 120];
            samples = radioPolls(testCase.Folder, at, ["failed"; "failed"; "no_service"], ...
                nan(3, 7), repmat("lte", 3, 1), zeros(3, 1));
            fig = mooring.plotRadio(samples, Visible="off");
            [names, found] = testCase.panels(fig);
            testCase.verifyNumElements(names, 5);
            % No band at all and two services: two rows each, and two
            % more for the times under the services.
            testCase.verifyEqual(testCase.layoutRows(found), [3; 3; 2; 2; 4]);
        end

        function aPanelOfNamesIsAsTallAsItsNamesNeed(testCase)
            samples = mooring.readRadioSamples(fixtureFile("radio-samples.csv"));
            events = mooring.readRadioEvents(fixtureFile("radio-events.csv"));

            % Three rows for the lines and two for the carriers. The
            % fixture's two bands take two rows, its four services three,
            % and two more are for the times under the last panel.
            fig = mooring.plotRadio(samples, Visible="off");
            [~, found] = testCase.panels(fig);
            testCase.verifyEqual(testCase.layoutRows(found), [3; 3; 2; 2; 5]);

            % With the events, theirs is the last panel: ten kinds of
            % change take six rows, five kinds four, three kinds three,
            % and no change at all two.
            kinds = [10, 5, 3, 0];
            last = [8, 6, 5, 4];
            for index = 1:numel(kinds)
                fig = mooring.plotRadio(samples, Events=events(1:kinds(index), :), Visible="off");
                [~, found] = testCase.panels(fig);
                testCase.verifyEqual(testCase.layoutRows(found), [3; 3; 2; 2; 3; last(index)]);
            end

            % The band panel follows the bands: five of them take four
            % rows. Three services take three.
            at = 1791918000 + 60 * (0:6)';
            kind = ["failed"; "no_service"; repmat("attached", 5, 1)];
            readings = [nan(2, 7); repmat([-95, -11, 12, -65, NaN, NaN, NaN], 5, 1)];
            bands = ["B3"; "B3"; "B1"; "B3"; "B7"; "B20"; "n78"];
            polls = radioPolls(testCase.Folder, at, kind, readings, repmat("lte", 7, 1), zeros(7, 1), ...
                repmat("234-30", 7, 1), bands);
            fig = mooring.plotRadio(polls, Visible="off");
            [~, found] = testCase.panels(fig);
            testCase.verifyEqual(testCase.layoutRows(found), [3; 3; 4; 2; 5]);
        end

        function onlyTheLastPanelNamesItsTimes(testCase)
            samples = mooring.readRadioSamples(fixtureFile("radio-samples.csv"));
            events = mooring.readRadioEvents(fixtureFile("radio-events.csv"));

            fig = mooring.plotRadio(samples, Visible="off");
            [~, found] = testCase.panels(fig);
            testCase.verifyNumElements(found, 5);
            testCase.verifyOnlyTheLastNamesItsTimes(found);

            fig = mooring.plotRadio(samples, Events=events, Visible="off");
            [~, found] = testCase.panels(fig);
            testCase.verifyNumElements(found, 6);
            testCase.verifyOnlyTheLastNamesItsTimes(found);
        end

        function aNameIsShownAsItIsSpelled(testCase)
            % The kinds of change are spelled with underscores, which the
            % default interpreter of tick labels reads as subscripts.
            samples = mooring.readRadioSamples(fixtureFile("radio-samples.csv"));
            events = mooring.readRadioEvents(fixtureFile("radio-events.csv"));
            fig = mooring.plotRadio(samples, Events=events, Visible="off");
            [names, found] = testCase.panels(fig);
            ofNames = [3, 5, 6];
            testCase.verifyEqual(names(ofNames), ...
                ["Band of the primary carrier"; "Service"; "Changes between polls"]);
            for index = ofNames
                testCase.verifyEqual(string(found(index).TickLabelInterpreter), "none");
            end
            % A panel without a mark is one of names too.
            fig = mooring.plotRadio(samples, Events=events([], :), Visible="off");
            [~, found] = testCase.panels(fig);
            testCase.verifyEqual(string(found(6).TickLabelInterpreter), "none");
        end

        function nothingToDrawIsRefused(testCase)
            samples = mooring.readRadioSamples(fixtureFile("radio-samples.csv"));
            testCase.verifyError(@() mooring.plotRadio(noRadioSamples(testCase.Folder)), ...
                "mooring:radio:NothingToPlot");
            testCase.verifyError(@() mooring.plotRadio(samples, Events=samples), "mooring:radio:NotEvents");
            % Neither refusal left a figure behind.
            testCase.verifyEmpty(findall(groot, "Type", "figure", "Name", "Mooring radio history"));
        end
    end
end
