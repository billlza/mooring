<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Runbook: the radio history in MATLAB

This runbook is for the operator. It covers printing the radio history as tables, taking the tables to another machine, and reading, plotting and analysing them in MATLAB with the package under `matlab/`.

The design is §15.6, rules 11 and 13. The radio history is what the daemon records of every poll of the M7, about one a minute while it runs: the signal's strength (RSRP, RSSI) and quality (RSRQ, SINR) for LTE and NR, the band, the number of secondary carriers, the service (5G or LTE, or none), the network's codes, the session's and the M7's uptime, the temperature, or why the poll failed. The newest 90 days are kept.

A table holds that and nothing more: no cell identity, no address, and nothing about a user. It does name the carrier's network by its codes, and it shows when the M7 was polled, up and attached. Keep a table as you keep the Mac's other files.

Below, `mooringctl` is the installed one, `~/Applications/Mooring.app/Contents/MacOS/mooringctl`. The `--csv` option is in builds made from 2026-11-14 on; an older build refuses it as an argument it does not know.

## 1. Print the tables on the Mac

```
~/Applications/Mooring.app/Contents/MacOS/mooringctl router history --csv samples > radio-samples.csv
~/Applications/Mooring.app/Contents/MacOS/mooringctl router history --csv events > radio-events.csv
```

- `samples` has one row per poll, `events` one row per change between polls: a poll that failed or recovered, service lost or regained, another band, service type or network, a restarted session, a reboot of the M7.
- Without dates the range is yesterday and today, UTC. `--since` and `--until` name the first and the last UTC day, and a range holds at most 90 days:

```
~/Applications/Mooring.app/Contents/MacOS/mooringctl router history --since 2026-10-16 --until 2026-11-14 --csv samples > radio-samples.csv
```

- The command reads the history's files and changes nothing. It needs no daemon, and a running daemon goes on recording.
- A day of polls is about 0.2 MB of samples.
- The first line of a table is its header, and the header is the format's version: a reader that knows another header refuses the file. Times are the Mac's, in UTC, once as seconds since 1970 and once as a stamp. An empty cell is a value the sample does not hold: a reading the M7 did not report, and everything a failed poll or a read without service could not give.
- If the command fails it prints no part of a table, and says why on the terminal.
- A table cannot say that the daemon was in the middle of writing a line. Such a line is no row; the next export has it. `mooringctl router history` without `--csv` names a day whose last line is incomplete.

## 2. Take the tables to another machine

The Mac sends. Nothing reaches into the Mac: the design gives it no inbound connection (§18), so there is no fetching the history from another machine by SSH into the Mac, and Mooring opens no port for it. Send from the Mac, to a machine of your own that the Mac can reach by SSH:

```
set -o pipefail
~/Applications/Mooring.app/Contents/MacOS/mooringctl router history --since 2026-10-16 --csv samples | ssh <machine> 'cat > radio-samples.csv'
~/Applications/Mooring.app/Contents/MacOS/mooringctl router history --since 2026-10-16 --csv events | ssh <machine> 'cat > radio-events.csv'
```

- **Never to a machine on a university network.** The session is operator traffic, and it would cross Janet (design F15, P0-2, §10.2). A machine at home, or one of your own elsewhere.
- Not to a Mooring node either: a node holds what the design sends it and no more (§15.5, §15.9).
- With `set -o pipefail` a line that ends with a status other than 0 did not send a whole table: `mooringctl` failed (the file on the other machine is then empty) or the connection broke (the file may be cut short). Send it again. MATLAB's reader refuses an empty file and a file that does not end with a line end, but it cannot tell a file cut exactly between two rows from a whole one, so look at the status.
- The other way is to carry the two files: AirDrop to your own Mac, or a USB stick.
- Nothing sends on a schedule. The history keeps 90 days, so an export every few weeks loses nothing.

## 3. Read the tables in MATLAB

The package is the folder `matlab/` of this repository: clone the repository on the other machine, or copy that folder. It needs no toolbox. Its tests run on MATLAB R2024b and R2026b.

```matlab
addpath("<the repository>/matlab")
samples = mooring.readRadioSamples("radio-samples.csv");
events = mooring.readRadioEvents("radio-events.csv");
```

`samples` is a timetable with a row per poll. Its row times, `samples.at`, are in UTC (`samples.Properties.RowTimes.TimeZone = "Europe/London"` shows them in local time). A number is a double, and NaN where the sample holds no value; a name is a categorical, and undefined where the sample holds none. `help mooring.readRadioSamples` lists the variables, and `summary(samples)` shows them.

Where MATLAB is on the exit Mac itself, one call runs `mooringctl` for both tables:

```matlab
[samples, events] = mooring.radioHistory(Days=30);
```

`Days` counts back from today, UTC, with today among them; `Since` and `Until` take days as `"2026-11-01"`; without any of them the range is the command's own, yesterday and today.

## 4. Look at it

```matlab
mooring.plotRadio(samples, Events=events);
```

Six panels over one time axis, which zoom and pan together: the signal (LTE RSRP, NR RSRP, LTE RSSI, in dBm), the quality (LTE and NR RSRQ and SINR, in dB), the band of the primary carrier, the number of secondary carriers, the service of each poll (failed, without service, on LTE, on 5G), and the events.

```matlab
hourly = mooring.radioHourly(samples);
plot(hourly.hour, hourly.lte_sinr_db)
```

`hourly` has a row for every UTC hour from the first sample's to the last sample's: how many polls it holds, how many failed, how many read without service and how many attached, the share of the attached polls on 5G, the mean number of secondary carriers, and the median of each reading. A value of no poll is NaN.

```matlab
networks = mooring.radioNetworks(samples);
```

`networks` has a row for each network the M7 was on, in the order of their first polls: the network's codes, its first and its last poll, how many UTC days hold a poll of it, and what `hourly` has, over the network's polls. After another SIM went into the M7 it sets the two networks side by side. A poll that holds no codes (a failed poll, a read without service) counts for the network of the last poll before it that holds them.

- Each network is taken over whatever hours it was polled in. For the same hours of the day, pass those polls alone: the evenings from 18:00 UTC are `mooring.radioNetworks(samples(hour(samples.at) >= 18, :))`.
- The medians say how the radio link read, not how fast it was: the history holds no throughput.
- What the real history showed on 2026-11-15, through a script that printed counts and shares only (21,346 polls: 17,005 on the network of the SIM before, over 13 days, and 4,341 on the present one's, in the 5 days since it went in on 2026-11-11). Of the attached polls, 49 % held an NR reading before and 87 % now. A secondary carrier was there in 34 % of the daytime's (07:00 to 18:00) before and in 57 % now, and in 26 % and 64 % of the evening's (18:00 to 24:00); at night (00:00 to 07:00) it was there in 24 % before and in 1.5 % now. The LTE carrier's SINR was below 0 dB in 17 % of the daytime's before and in 39 % now. Of all the evening's polls 5.7 % failed before and 0.2 % now (a failed poll is the Mac not reading the M7, whatever the cause). Five days beside thirteen, and no throughput: a look, not a measurement.

The columns are ordinary MATLAB data, so the rest of MATLAB works on them: `groupsummary(samples, "band", "median", "lte_sinr_db")`, `histogram(samples.lte_rsrp_dbm)`, `retime`, and so on.

## 5. Is the link worse than it was

```matlab
[indicators, verdict, network] = mooring.radioDegradation(samples);
```

It sets the last 24 hours, counted back from the last sample, beside the same 24 hours of each of the 7 days before. With the defaults it looks at 8 days of history, and it needs 3 earlier days at least.

It judges one network at a time: the polls of the network the last poll was on, whose codes `network` gives. Another network's days are no baseline for this one's. So after another SIM went into the M7 every indicator is `insufficient_data` until 3 earlier days on the new network count, which is four days after the change. `Network="234-20"` judges another network by its codes, its last 24 hours counted back from its own last poll. `Network="all"` judges every poll whatever its network, as the function did before 2026-11-15. A poll that holds no codes counts for the network of the last poll before it that holds them.

`indicators` has a row per indicator: the median of each reading, the share of the polls that failed, the share of the reads without service, the share of the attached polls on 5G, and the mean number of secondary carriers. For each it gives:

| Variable | Meaning |
|---|---|
| `recent` | The indicator over the last 24 hours |
| `baseline` | The median of the indicator over each earlier day: what a usual day shows |
| `change` | `recent` less `baseline` |
| `threshold` | The change that matters. It is yours to set |
| `spread` | The median of how far the earlier days lie from the baseline: how much this link's days differ anyway |
| `worse_when` | `lower` or `higher` |
| `recent_count` | The polls with a value in the last 24 hours |
| `baseline_days` | The earlier days that count: those with 30 polls with a value or more, and a poll in their first hour |
| `state` | See below |

| State | Meaning |
|---|---|
| `degraded` | Worse than the baseline by the threshold or more, and by more than three times the spread |
| `ok` | Not so |
| `insufficient_data` | The last 24 hours hold fewer than 30 polls with a value, or fewer than 3 earlier days count |

`verdict` is `"degraded"` when an indicator is, else `"ok"` when one is ok, else `"insufficient_data"`.

- The spread is there because a threshold alone says "degraded" for an indicator that swings from day to day anyway. On the 16 days of history the Mac held on 2026-11-14, judged at the end of each of the last 9 days, the thresholds alone called an indicator degraded on 8 of the 9, mostly the share on 5G. With the spread it was 5 of the 9: one day for the LTE SINR, one for the failed polls, and three days in a row on which fewer than 30 polls a day held an NR reading. `SpreadFactor=0` leaves the thresholds to decide alone, and `SpreadFactor=2` asks for less than three times.
- That look took every poll, and it spanned the change of SIM on 2026-11-11: its day for the LTE SINR set the new network's polls against the old network's baseline, and its day for the failed polls held the change itself. Looked at again on 2026-11-15 (21,346 samples, judged at the history's end and at the same time of each of the 14 days before): with every poll 8 of the 15 were `degraded`, 5 `ok` and 2 `insufficient_data`; by network 6, 3 and 6. The 6 are the old network's: its last three days for the share on 5G and the secondary carriers, two days for the LTE RSSI and one for the share on 5G. The four since the change are `insufficient_data`.
- An earlier day counts when its 24 hours hold 30 polls with a value or more, and a poll in their first hour. A day the polls begin in later is a part of a day, and its hours are not the last 24 hours' hours: the day another SIM went in, and the day the history begins. On 2026-11-15 the day the present SIM went in held the new network's polls in 4 of its 24 hours, the late evening's, when that network has the most secondary carriers; counted as the third earlier day, it made the secondary carriers read `degraded`. Only the first hour is looked at: a day with hours without a poll inside it still counts.
- A link that became worse and stays worse is `degraded` for four days. After that, four of the seven earlier days are as bad, and the bad level is the baseline. For a longer look back, plot the indicator: `plot(hourly.hour, hourly.lte_sinr_db)`.
- The thresholds are starting points, not measurements of this link: 3 dB of RSRP, SINR and RSSI, 2 dB of RSRQ, 5 points of failed polls and of reads without service, 20 points of 5G, half a secondary carrier. Compare them with `change` and `spread` over a few quiet weeks and set your own (`help mooring.radioDegradation` lists the arguments, such as `SinrDrop=4`). A threshold of `Inf` leaves its indicators out.
- A change of band moves the readings' level without the link being worse or better, and so does a change of network where every poll is taken (`Network="all"`). Look at `events` before you read a `degraded`.
- `Recent=hours(6)` compares a shorter window (24 hours at most) with the same hours of the earlier days. `Days=14` takes more days into the baseline.
- For the state at an earlier time, give it the samples up to then: `mooring.radioDegradation(samples(samples.at <= t, :))`.

## 6. The coming hours

```matlab
[forecast, fit] = mooring.radioForecast(samples, Metric="lte_sinr_db");
plot(forecast.hour, forecast.expected, forecast.hour, [forecast.low, forecast.high], "--")
```

It forecasts the hourly median of one reading for the 48 hours after the last sample, from the hourly medians of the 14 days before. The forecast of an hour is the daily pattern: the median of the history's values of that hour of the day. `forecast.low` and `forecast.high` are the band that held 80 % of the history's hours around the fit.

- It fits one network's polls, the network of the last poll, as section 5 judges them; `fit.network` gives its codes, and `Network="234-20"` and `Network="all"` are as there. After another SIM went into the M7 the history is the hours since. Until they hold 72 hourly medians the function refuses (`mooring:radio:TooFewHours`, naming the network): for three days at least. With every poll taken, an hour of the day's median lies between the two networks' levels.
- It is the history's description continued. It knows nothing of what changes a link (another band or cell, the M7 moved), and the band does not widen with the distance ahead.
- `fit` says how far to trust it. `fit.backtest_mae` is the forecast's mean error on the history's own last 48 hours, made without them. `fit.naive_mae` is the same for "as at the same hour of the day before". Where the first is not the smaller of the two, the fit adds nothing to yesterday.
- `fit.slope_per_day` is how the history's level moved, in dB (or dBm) a day. The forecast does not continue it unless you pass `Trend=true`. On the history of 2026-11-14, forecasts made every 6 hours had 67 % to 100 % of the error of "as at the same hour of the day before" without the slope. With it the NR SINR's forecast was better (80 % to 82 %, where the pattern alone had 96 % to 100 %), the NR RSRP's was worse than "as at the same hour of the day before" itself (113 % to 122 %), and the other readings' moved by 4 points at most. That look took every poll and spanned the change of SIM. On 2026-11-15, over the old network's polls alone, the pattern had 66 % to 108 % of that error at 24 hours ahead and 69 % to 108 % at 48, above 100 % for the LTE RSRP only; with the slope the NR RSRP's error was 140 % and 157 %, and the other readings' moved by 6 points at most. The new network's hours were too few for a backtest. A level that moved in one step, as with another band, reads as a slope and is continued wrongly. Compare `fit.backtest_mae` of the two fits before you use the trend.
- `fit.profile` is the pattern, 00 to 23 UTC.
- It needs 72 hourly medians (`MinHours`, at least 48), and its backtest 72 before the last 48. An hour of the day the history never held has no forecast: NaN.
- `Horizon=hours(24)` and `History=days(30)` change how far it looks ahead and back.

## 7. When a function refuses

Every refusal is an error with an identifier; nothing is guessed and nothing half-read is returned.

| Identifier | What happened | What to do |
|---|---|---|
| `mooring:radio:NoFile` | There is no such file | Check the path |
| `mooring:radio:Incomplete` | The file is empty or does not end with a line end | The export or the transfer was cut short: export again |
| `mooring:radio:UnknownHeader` | The first line is not the header this package reads; the message shows the line found and the header expected | The events table was given for the samples or the other way round; or `mooringctl` and the package are of different builds: take both from one commit |
| `mooring:radio:BadRow` | A line is not a row of the table; the message gives its number | The file was edited or damaged: export again |
| `mooring:radio:TimeMismatch` | A row's two times differ | As above |
| `mooring:radio:NotSamples` | The timetable is not one `readRadioSamples` returned | Pass the samples, not the events or the hourly table |
| `mooring:radio:TooFewHours` | A forecast has fewer hourly medians than it needs, on the network it fits | Export a longer range, or pass `MinHours`; after a change of SIM, wait for the new network's hours |
| `mooring:radio:UnknownNetwork` | `Network` names codes no poll is on; the message lists the networks the samples hold | Pass one of them, `"last"` or `"all"`; `mooring.radioNetworks(samples)` shows them |
| `mooring:radio:NoMooringctl`, `mooring:radio:CommandFailed` | `radioHistory` found no `mooringctl`, or the command failed; the message holds what it said | On another machine read exported tables instead |

An argument that cannot be meant has its own identifier: `mooring:radio:BadDay`, `DaysAndRange`, `BadWindow`, `BadHorizon`, `UnknownMetric`, `NothingToPlot` and `NotEvents`, each with a message that says what it wants.

## 8. What is checked, and what is not

- The tables: `mooringctl`'s tests pin them byte for byte, read every table back into the samples it was made from, and are mutation-checked.
- The package: its tests run on a hosted runner (`.github/workflows/matlab.yml`), on the two golden tables of `contract/history-fixtures`, which are what the command prints for the fixture's samples, and on made-up polls. A warning fails a test, and the package's files are held to 95 % line coverage.
- The real history, without MATLAB (2026-11-14): a script matched every row of both tables of the 16 days the Mac held (19,937 samples, 578 events) against the reader's patterns, and Python ports of `radioDegradation` and `radioForecast` ran over the samples, printing counts and ratios only. On 2026-11-15 the ports ran again, with the rules by network, over the 21,346 samples the Mac then held. Sections 4, 5 and 6 give what they showed.
- The installed command, on the day it was deployed (2026-11-14): `router history --csv samples` and `--csv events` ended with exit code 0 on the real history, each with the header this package reads; only the row counts were looked at.
- Not checked: the MATLAB code on the real history; the figure, by eye; `radioHistory` with the real `mooringctl` (its tests use a stand-in); MATLAB on macOS (the runner is Linux). Sixteen days of one link are a look at the thresholds and the forecast, not a calibration.
