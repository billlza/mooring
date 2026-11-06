<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# The user portal's two files

The user portal is a separate web application. It shows each user who has an account there the state of their service, and hands them their CFM file by download or by subscription link. It never reads Mooring's state, usage files or keychain. Mooring writes two files for it, and the operator imports them on the portal's host:

| File | Command | Holds credentials | Portal import |
|---|---|---|---|
| Snapshot, `mooring-portal-snapshot` version 1 | `mooringctl portal export --user <id>... --out <path>` | no | `mooring-portal import` |
| Profile bundle, `mooring-portal-cfm-profiles` version 2 | `mooringctl user export-profiles --user <id>... --out <path>` | yes | `mooring-portal import-profiles` |

Both files hold only the users the operator names, those bound to an account at the portal. A user with no account there, delivered by file only, is never named, so nothing about them reaches the portal's host.

This page is Mooring's statement of both formats, complete without the portal's repository. The portal defines them, in its `docs/contract/portal-snapshot-v1.md` and `docs/contract/cfm-profiles-v2.md`. This page follows those documents at the portal's commit `120ca8a`. The snapshot's format and valid goldens there are the same as at `c070413`, where its copies below were taken. The bundle's format and valid goldens are those of `520c358`, where its copies were taken; `120ca8a` changed only what the import does to a withheld user's subscription link (§3.2). Changing a key, a value or a rule is a new version in the portal's contract, and then here.

Design §9.5 places the exporters in Mooring.

## 1. The agreement comes first

Revision 1 of the user agreement (`docs/runbooks/user-agreement.md`) does not cover the portal:

- Clause 4 lists every place a user's data is kept, and the portal's host on the internet is not among them.
- Clause 2 tells users never to paste a link.
- Clause 5 says the service has no subscription link.

So both commands refuse everything until a revision that covers the portal is written and accepted. The refusal is built into the exporters' types and checked on the built binary:

- `mooring_model::PORTAL_AGREEMENT_SINCE` names the first revision that covers the portal. It is `None`, so `PortalAgreement::SHIPPED`, which the binary passes to both exporters, is closed.
- Both commands check the gate first, before they read the state. The pure exporters check it again (`mooring-daemon-core`'s `portal::snapshot` and `mooring-export`'s `profile_selection` and `export_profiles`).
- `PortalAgreement::since` builds a gate from an explicit revision, which tests use to open it. No product code calls it; `crates/mooringctl/tests/shipped/portal_gate.rs` runs the built binary and requires both commands to refuse with the gate's message, so what `main` passes is checked, not only the types.
- Once the gate opens, a user's data and file go to the portal only once the user has accepted that revision, `AgreementVersion::CURRENT`: the snapshot refuses a user named without that acceptance, and the bundle withholds them (§3.2). A user export requires the same (decision F9).
- While the gate is closed, the bundle is refused whole. It is never written with every user withheld for want of an acceptance that cannot be had yet: such a bundle is valid, and its import would pause every bound user's subscription link.
- `crates/export/tests/export/agreement_text.rs` ties the gate to the text. The gate is open exactly when the user-visible text names the portal (门户). The text's SHA-256 is pinned in the same file, so a revised text needs a new revision.

Writing the revision (see the operator notes of `user-agreement.md`) sets `PORTAL_AGREEMENT_SINCE`, raises `AgreementVersion::CURRENT` and records the new digest, all in one commit. Every user then accepts it again (`user agree`) before anything about them goes to the portal.

## 2. The snapshot

### 2.1 Document

One UTF-8 JSON object, at most 1 MiB. Every key is always present; a value that is unknown or absent is `null`, never 0. The portal refuses any other key.

| Key | Value | From |
|---|---|---|
| `format` | `"mooring-portal-snapshot"` | constant |
| `version` | `1` | constant |
| `generated_at` | Unix seconds | the export's time, the Mac's clock |
| `cycle` | `{"start": "YYYY-MM-DD", "next_start": "YYYY-MM-DD"}` | the SIM billing cycle on the UTC calendar (`BillingCycle`): the usage report's cycle, or without a report the cycle `generated_at` is in (`BillingCycle::of_instant`) |
| `counted_through` | Unix seconds or `null` | the usage report's `UsagePeriods::through`, the instant its figures are reported as of; `null` without a report |
| `users` | array, at least one | the users named, in id order |

Each user:

| Key | Value | From |
|---|---|---|
| `user` | the 10-character `UserId` | `User::id`; never the label or the public alias (clause 4 keeps those on the Mac) |
| `status` | `"active"`, `"revoked"` or `{"suspended": {"reason": …, "since": …}}` | `UserStatus`: `RevokePending` and `Revoked` are both `"revoked"`; reasons `operator`, `quota_exceeded` (without the cycle it names), `expired`, `abuse_review` |
| `cycle_served_bytes` | integer or `null` | `UserUsage::cycle_served_bytes` from the report; `null` without a report, or when the report cannot establish it |
| `reality_downlink_counted_at_close` | boolean | `UsageAccuracy::of`: true while the user is served, since REALITY's spliced downlink is counted only when a connection closes |
| `quota` | `{"cycle_served_bytes": >0, "warn_percent": 1–99, "action": "warn"\|"suspend"}` or `null` | `effective_quota` with the automatic quota of `generated_at`: the user's own quota, or the deployment's automatic one, or none |
| `expires_at` | Unix seconds or `null` | `UserPolicy::expires_at` |

The status line (`daemon-core`'s `snapshot::assemble`) uses the same functions, so the portal shows each user what the console shows the operator at the same instant.

### 2.2 Rules

Mooring refuses to write a snapshot that breaks one; the portal refuses it on import.

1. Only the users named, at least one, each known, each once (`mooring_model::named_users`, the rule both files follow), each with an acceptance of the required revision (§1). Not every user by default: the portal keeps records only for users bound to an account there, and the operator names those.
2. `cycle.start` is before `cycle.next_start`, and not after `generated_at`.
3. `counted_through`, when not `null`, lies within the cycle (both ends included) and not after `generated_at`.
4. Without a report every `cycle_served_bytes` is `null`.
5. No suspension is dated after `generated_at` (the Mac's clock wrote both; a later one means it stepped back).
6. Every instant and date lies between 1970-01-01 and 9999-12-31.

### 2.3 Usage

The command aggregates the usage the daemon collected (`usage/users.json`) at the export's time, exactly as the status line does (`CollectedUsage::aggregate`). The daemon pulls each node's usage about once a minute, and a report needs every serving node's latest sample to be at most three minutes old.

When the collection is behind, there is no report, and the snapshot is still written without usage figures. That is the case when the daemon has not collected a serving node's usage yet, or not within those three minutes (it is stopped, or a node is unreachable). Every figure and `counted_through` is then `null`, the portal shows each user's usage as unknown, and the command prints the reason as a warning.

A fault is different. The file cannot be read, does not decode, or its figures contradict each other or the deployment. Then nothing is written, because null figures at the portal would replace each user's last good figures and hide the fault.

### 2.4 Goldens

`contract/portal-fixtures/snapshot-v1/pilot.json` and `no-usage-report.json` are byte-for-byte copies of the portal's `contract/fixtures/v1/valid/` at its commit `c070413`, with synthetic data only. `crates/daemon-core/src/tests/portal/mod.rs` makes the same snapshots from a deployment of those seven users and compares the bytes.

## 3. The profile bundle

### 3.1 Document

One UTF-8 JSON object, at most 1 MiB, every key always present and no other:

| Key | Value |
|---|---|
| `format` | `"mooring-portal-cfm-profiles"` |
| `version` | `2` |
| `generated_at` | Unix seconds, the export's time |
| `profiles` | array, possibly empty: `{"user": <UserId>, "document": <object>}` per user delivered, in id order |
| `withheld` | array, possibly empty: `{"user": <UserId>, "reason": "suspended" \| "revoked" \| "agreement_not_accepted"}` per user withheld, in id order |

The two arrays name at least one user between them, and no user twice, in one array or across both. The portal does not depend on the entries' order.

Each `document` is the user's CFM file exactly as `user export` writes it in the default format (`ExportFormat::SingBoxJson`, design §9.1). It is a sing-box node list whose only key is `outbounds`, built by the same function from the same checked outbounds. The portal stores each document's text as it stands in the bundle and serves it unchanged, at most 64 KiB of it. A document holds at most 2 nodes × 3 outbounds (`MAX_ACTIVE_NODES`, `MAX_HY2_LISTENERS`), a few KiB, but the export still measures each one as the portal does and refuses one past the bound.

Version 1, which Mooring wrote from PR #24 (main `d478e91`) until version 2, held every user to be served and had no `withheld`. It was never imported anywhere, since the gate was closed, and the portal now refuses it as "version 1".

### 3.2 Who is in it

A bundle holds exactly the users the operator names, each once, and those are the users bound to an account at the portal. Mooring cannot tell who is bound, so the operator names them: `mooring-portal --db <file> bound-users` on the portal's host prints every bound account's user as `--user <id>` arguments, in id order, ready to follow the export command. The portal refuses, whole and changing nothing, a bundle that does not name every bound account's user, so a user left off the list costs a second export, never a link. The command refuses a list that names no one, an id no user has (most likely mistyped) or a user twice (`NamedUsersError`), and writes nothing.

Each user named is on exactly one side. An exhaustive match on `UserStatus`, with no wildcard, decides which: a status added later has to be placed, after the contract says where.

- **Delivered (`profiles`):** an `Active` user with an acceptance of the required revision (§1). Each passes every check of `user export` (design §9.2): its capabilities, its credentials, and each node's generation, certificate and address.
- **Withheld (`withheld`), and named in the output with the reason:** a suspended user, whatever the reason, as `suspended` (the snapshot carries the reason); a user being revoked or revoked as `revoked`, as in the snapshot; an active user without the acceptance as `agreement_not_accepted`.
- **Refused:** a bundle in which a user to be delivered cannot have a file (a node not applied at the current generation, a certificate no longer current, no credentials). None of the contract's reasons to withhold a user is theirs, and leaving them out would make the portal refuse the bundle, so nothing is written.

A bundle that withholds every user named is still written, with `profiles` empty: the portal stops serving them on import.

On import, a bound user who is withheld is no longer served a profile. What becomes of their subscription link depends on the reason (the operator's decision, 2026-11-06), and the command says it for each user withheld:

- `suspended`, whatever the suspension's reason (quota, expiry, review or the operator's), and `agreement_not_accepted` pause the link. Once the user is resumed, or accepts the revision, and a bundle delivers them again, the same link serves their document again, and the user chooses Update in CFM. A suspension for quota pauses until the next billing cycle. Mooring is to lift it at the first apply of the new cycle (design §13.6, M5), which is not built yet: until then the operator resumes the user and exports the bundle again.
- `revoked` ends the link for good. A ban for illegal use is a revocation here and, at the portal, a separate step by the operator, which also bars the person from registering again. Mooring's revocation records no reason, and a user who leaves is revoked too, so the portal never takes a revocation for a ban.

A paused link answers 404, as an unknown one does, and while it is paused the user cannot generate a new link at the portal. The portal's contract and import work this way since its commit `120ca8a`; the bundle's format did not change.

A user named but bound to no account is not stored, and the portal reports them; if they were delivered, the file has carried their credentials to its host, and the import says to delete it at once.

As for `user export`, every check runs before the file is looked at, and the file is checked before the keychain is read. Then exactly the delivered users' secrets are read (`ProfileSelection::secret_refs`), and none of a withheld or unnamed user's.

The bundle is exported again whenever its set or a file in it changes: a user is bound or unbound at the portal, added (once every node is applied), suspended, resumed, revoked, or accepts a new revision, and after every change that changes a user's file (`delivery.md`, section 7). After a new revision of the agreement, a bound user who has not accepted it yet is withheld, and their link pauses until they accept and a bundle delivers them again, so the bundle need not wait until every bound user has accepted. The snapshot does not withhold: it refuses a user named without the acceptance (§2.2), so until a user accepts, the operator leaves them out of its list, and the portal keeps their last snapshot.

### 3.3 Goldens

`contract/portal-fixtures/cfm-profiles-v2/pilot.json` and `all-withheld.json` are byte-for-byte copies of the portal's `contract/fixtures/cfm-profiles-v2/valid/` at `520c358`. No export can produce their values: they use a documentation address and a pin of the wrong length. So `crates/export/tests/export/profiles.rs` compares bundles of the fixture deployment with them key by key and type by type, at every level and for both protocols, whatever the entries' order, and the format, the version and each withheld reason by value. Each document is compared with the user's own `user export`. The portal's `invalid/` fixtures for this contract are cases of its own parsing, `version-1.json` among them: none is a document Mooring writes.

## 4. The files

Both commands write as `user export` does (`crates/mooringctl/src/export_file.rs`):

- a new file with mode 0600, never one that exists, removed again if writing fails;
- a warning when its folder is in iCloud Drive, a cloud folder, the Desktop or Documents, or is backed up by Time Machine.

The bundle holds every delivered user's credentials. Carry it to the portal's host as an export file is carried (`delivery.md`, section 0), import it, and delete it on both machines. The snapshot holds no credentials, but it ties user ids to their status and usage, so it is handled the same way.
