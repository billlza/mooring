function samples = readRadioSamples(file)
%READRADIOSAMPLES The radio samples of a table mooringctl printed.
%   SAMPLES = mooring.readRadioSamples(FILE) reads the file that
%
%       mooringctl router history --csv samples > FILE
%
%   wrote: one row per poll of the M7, about one a minute. SAMPLES is a
%   timetable whose row times, `at`, are the Mac's times of the polls in
%   UTC. Its variables are the table's columns. A number is a double, and
%   NaN where the sample holds no value: a reading the M7 did not report,
%   and everything a failed poll or a read without service could not give.
%   A name is a categorical, and undefined where the sample holds none.
%
%     outcome             read | failed
%     failure             why a failed poll failed
%     uptime_secs         the M7's uptime
%     temperature_c       the M7's temperature
%     thermal             the M7's thermal state
%     service             attached | no_service
%     network_service     nr5g | lte
%     data_service        nr_sub6 | lte | lte_plus
%     band                the primary carrier's band, as B3 or n78
%     ca_secondary_count  how many secondary carriers were aggregated
%     lte_rsrp_dbm, lte_rsrq_db, lte_sinr_db, lte_rssi_dbm
%     nr_rsrp_dbm, nr_rsrq_db, nr_sinr_db
%     plmn                the network's codes, as 234-30
%     session_secs        the data session's length
%
%   The file is read strictly: one whose first line is not the header this
%   package knows, or that holds a line that is no row, is refused with an
%   error and nothing is returned (see mooring.internal.readCsv).
%
%   See also mooring.readRadioEvents, mooring.radioHistory,
%   mooring.radioHourly, mooring.radioDegradation, mooring.radioForecast,
%   mooring.plotRadio.

% SPDX-License-Identifier: GPL-3.0-or-later

    arguments
        file (1,1) string
    end
    layout = mooring.internal.radioFormat("samples");
    samples = mooring.internal.asTimetable(mooring.internal.readCsv(file, layout), layout);
end
