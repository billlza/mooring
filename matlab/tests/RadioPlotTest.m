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
            testCase.verifyNumElements(testCase.panels(fig), 5);
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
