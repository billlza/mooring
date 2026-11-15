classdef RadioNetworksTest < matlab.unittest.TestCase
%RADIONETWORKSTEST Each network's polls and median readings, side by side.

% SPDX-License-Identifier: GPL-3.0-or-later

    properties (Constant)
        % 2026-10-13 19:00:00 UTC.
        Base = 1791918000
        Names = ["network", "first", "last", "days", "polls", "failed", "no_service", ...
            "attached", "nr5g_share", "ca_secondary_mean", "temperature_c", "lte_rsrp_dbm", ...
            "lte_rsrq_db", "lte_sinr_db", "lte_rssi_dbm", "nr_rsrp_dbm", "nr_rsrq_db", "nr_sinr_db"]
        % What a poll reads where a test is not about the readings.
        Steady = [-95, -10, 10, -60, NaN, NaN, NaN]
    end

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
        function samples = twoNetworks(testCase, order)
            % From 19:00 two polls on 234-20 and a failed one; a day later
            % a read without service and three polls on 234-30; two days
            % after that a failed poll. In the given order.
            at = testCase.Base + [0; 60; 120; 86400; 86460; 86520; 86580; 259200];
            kind = ["attached"; "attached"; "failed"; "no_service"; ...
                "attached"; "attached"; "attached"; "failed"];
            readings = [ ...
                -100, -12, 2, -69, NaN, NaN, NaN; ...
                -102, -14, 4, -71, NaN, NaN, NaN; ...
                nan(2, 7); ...
                -90, -9, 12, -60, -85.5, -10.5, 15.5; ...
                -92, -11, 14, -62, -87.5, -11.5, 17.5; ...
                -94, -10, 16, -64, NaN, NaN, NaN; ...
                nan(1, 7)];
            service = ["lte"; "lte"; "lte"; "lte"; "nr5g"; "nr5g"; "lte"; "lte"];
            carriers = [0; 1; 0; 0; 2; 2; 0; 0];
            codes = ["234-20"; "234-20"; ""; ""; "234-30"; "234-30"; "234-30"; ""];
            samples = radioPolls(testCase.Folder, at(order), kind(order), readings(order, :), ...
                service(order), carriers(order), codes(order));
        end

        function samples = attached(testCase, at, sinr, codes)
            % Attached polls at `at`, each with its SINR and its
            % network's codes.
            count = numel(at);
            readings = repmat(testCase.Steady, count, 1);
            readings(:, 3) = sinr;
            samples = radioPolls(testCase.Folder, at, repmat("attached", count, 1), readings, ...
                repmat("lte", count, 1), zeros(count, 1), codes);
        end
    end

    methods (Test)
        function eachNetworkIsARowWithItsPollsAndTheMediansOfItsReadings(testCase)
            networks = mooring.radioNetworks(testCase.twoNetworks(1:8));

            testCase.verifyClass(networks, "table");
            testCase.verifyEqual(string(networks.Properties.VariableNames), testCase.Names);
            testCase.verifyEqual(networks.network, ["234-20"; "234-30"]);
            testCase.verifyEqual(string(networks.first.TimeZone), "UTC");
            testCase.verifyEqual(string(networks.last.TimeZone), "UTC");
            % The failed poll and the read without service that follow the
            % polls on 234-20 are its own, a day apart; the failed poll at
            % the end is 234-30's, two days after its others, and the day
            % between holds no poll.
            testCase.verifyEqual(posixtime(networks.first), testCase.Base + [0; 86460]);
            testCase.verifyEqual(posixtime(networks.last), testCase.Base + [86400; 259200]);
            testCase.verifyEqual(networks.days, [2; 2]);
            testCase.verifyEqual(networks.polls, [4; 4]);
            testCase.verifyEqual(networks.failed, [1; 1]);
            testCase.verifyEqual(networks.no_service, [1; 0]);
            testCase.verifyEqual(networks.attached, [2; 3]);
            testCase.verifyEqual(networks.nr5g_share, [0; 2 / 3], "AbsTol", 1e-12);
            testCase.verifyEqual(networks.ca_secondary_mean, [0.5; 4 / 3], "AbsTol", 1e-12);
            testCase.verifyEqual(networks.temperature_c, [44; 44]);
            testCase.verifyEqual(networks.lte_rsrp_dbm, [-101; -92]);
            testCase.verifyEqual(networks.lte_rsrq_db, [-13; -10]);
            testCase.verifyEqual(networks.lte_sinr_db, [3; 14]);
            testCase.verifyEqual(networks.lte_rssi_dbm, [-70; -62]);
            testCase.verifyEqual(networks.nr_rsrp_dbm, [NaN; -86.5]);
            testCase.verifyEqual(networks.nr_rsrq_db, [NaN; -11]);
            testCase.verifyEqual(networks.nr_sinr_db, [NaN; 16.5]);
        end

        function theOrderOfThePollsDoesNotCount(testCase)
            inOrder = mooring.radioNetworks(testCase.twoNetworks(1:8));
            shuffled = mooring.radioNetworks(testCase.twoNetworks([8 3 1 6 2 7 5 4]));
            testCase.verifyTrue(isequaln(shuffled, inOrder));
        end

        function aNetworkTheM7CameBackToIsOneRow(testCase)
            % An hour on 234-30, one on 234-20, and the same again.
            at = testCase.Base + 3600 * (0:3)';
            networks = mooring.radioNetworks(testCase.attached(at, [2; 10; 4; 14], ...
                ["234-30"; "234-20"; "234-30"; "234-20"]));
            % In the order of their first polls, not of their codes.
            testCase.verifyEqual(networks.network, ["234-30"; "234-20"]);
            testCase.verifyEqual(posixtime(networks.first), testCase.Base + [0; 3600]);
            testCase.verifyEqual(posixtime(networks.last), testCase.Base + [7200; 10800]);
            testCase.verifyEqual(networks.days, [1; 1]);
            testCase.verifyEqual(networks.polls, [2; 2]);
            testCase.verifyEqual(networks.lte_sinr_db, [3; 12]);
        end

        function aPollWithoutCodesIsOfTheNetworkBeforeIt(testCase)
            % An attached poll whose codes the M7 did not report, between
            % a poll on 234-20 and one on 234-30.
            at = testCase.Base + [0; 60; 120];
            networks = mooring.radioNetworks(testCase.attached(at, [2; 4; 10], ["234-20"; ""; "234-30"]));
            testCase.verifyEqual(networks.network, ["234-20"; "234-30"]);
            testCase.verifyEqual(networks.polls, [2; 1]);
            testCase.verifyEqual(networks.attached, [2; 1]);
            testCase.verifyEqual(networks.lte_sinr_db, [3; 10]);

            % Before the first poll that holds codes there is no network
            % before: a failed poll and a read without service there are
            % of that poll's.
            samples = radioPolls(testCase.Folder, at, ["failed"; "no_service"; "attached"], ...
                repmat(testCase.Steady, 3, 1), repmat("lte", 3, 1), zeros(3, 1), ...
                [""; ""; "234-20"]);
            networks = mooring.radioNetworks(samples);
            testCase.verifyEqual(networks.network, "234-20");
            testCase.verifyEqual(posixtime(networks.first), testCase.Base);
            testCase.verifyEqual(posixtime(networks.last), testCase.Base + 120);
            testCase.verifyEqual(networks.polls, 3);
            testCase.verifyEqual(networks.failed, 1);
            testCase.verifyEqual(networks.no_service, 1);
            testCase.verifyEqual(networks.attached, 1);
        end

        function theSameHoursOfTheDayAreSetBesideEachOther(testCase)
            % At 19:00 and at midnight, a day on 234-20 and a day on
            % 234-30.
            at = testCase.Base + [0; 18000; 86400; 104400];
            samples = testCase.attached(at, [2; 10; 4; 14], ["234-20"; "234-20"; "234-30"; "234-30"]);

            networks = mooring.radioNetworks(samples);
            testCase.verifyEqual(networks.polls, [2; 2]);
            testCase.verifyEqual(networks.lte_sinr_db, [6; 9]);
            % The evenings alone, as the function's help gives them.
            networks = mooring.radioNetworks(samples(hour(samples.at) >= 18, :));
            testCase.verifyEqual(networks.network, ["234-20"; "234-30"]);
            testCase.verifyEqual(networks.polls, [1; 1]);
            testCase.verifyEqual(networks.lte_sinr_db, [2; 4]);
        end

        function samplesWithoutANetworksCodesAreOneRowWithoutAName(testCase)
            at = testCase.Base + [0; 60; 3600];
            samples = radioPolls(testCase.Folder, at, ["failed"; "no_service"; "failed"], ...
                nan(3, 7), repmat("lte", 3, 1), zeros(3, 1));
            networks = mooring.radioNetworks(samples);
            testCase.verifyEqual(height(networks), 1);
            testCase.verifyClass(networks.network, "string");
            testCase.verifyTrue(ismissing(networks.network));
            testCase.verifyEqual(posixtime(networks.first), testCase.Base);
            testCase.verifyEqual(posixtime(networks.last), testCase.Base + 3600);
            testCase.verifyEqual(networks.days, 1);
            testCase.verifyEqual(networks.polls, 3);
            testCase.verifyEqual(networks.failed, 2);
            testCase.verifyEqual(networks.no_service, 1);
            testCase.verifyEqual(networks.attached, 0);
            testCase.verifyEqual(networks.temperature_c, 44);
            for name = ["nr5g_share", "ca_secondary_mean", testCase.Names(12:end)]
                testCase.verifyEqual(networks.(name), NaN, name);
            end
        end

        function noSamplesAreNoNetworks(testCase)
            networks = mooring.radioNetworks(noRadioSamples(testCase.Folder));
            testCase.verifyClass(networks, "table");
            testCase.verifyEqual(height(networks), 0);
            testCase.verifyEqual(string(networks.Properties.VariableNames), testCase.Names);
            testCase.verifyClass(networks.network, "string");
            testCase.verifyEqual(string(networks.first.TimeZone), "UTC");
            testCase.verifyEqual(string(networks.last.TimeZone), "UTC");
        end

        function aTimetableThatIsNotOfSamplesIsRefused(testCase)
            events = mooring.readRadioEvents(fixtureFile("radio-events.csv"));
            testCase.verifyError(@() mooring.radioNetworks(events), "mooring:radio:NotSamples");
        end
    end
end
