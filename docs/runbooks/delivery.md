<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Runbook: delivering a user's file

This runbook is for the operator. It covers a user's first file, every later file, and what to do after a leak or a seizure.

The rules come from design §9.2, §9.4, §13.4, §13.5 and §13.6, and from decisions F9–F11. The operator delegated those decisions to the recommended default on 2026-10-15 (§20.2).

Of the commands named here only `hdiutil` and `tmutil` exist today. Every `mooringctl` command below (`user …`, `node apply`, `apply`, `doctor`) arrives in M5, and so does the console's rotation tracker. Until then this runbook is the procedure they will follow.

## 0. Once, on the operator's Mac

Make one folder for exports, outside iCloud Drive, Desktop and Documents, and keep it out of Time Machine, so that no backup keeps a file after it is deleted (design §12):

```
mkdir -m 700 <exports>
tmutil addexclusion <exports>
tmutil isexcluded <exports>
```

The last command must print `[Excluded]`.

## 1. Before any file

1. **The user's CFM.**
   - The user runs CFM on an Apple-silicon Mac with macOS 15 or later: CFM is arm64 only from 15.0.
   - The CFM build must be a 0.5-line release that has the mainland China direct switch (F10): CFM 0.5.0 (build 50030, tag `v0.5.0`, released 2026-10-18) or a later 0.5.x. The switch is `d828f92`; 0.5.0 is the first release with it.
   - Do not deliver a file to an older CFM. Without the switch, mainland sites fail, because the nodes deny `geoip:cn` and `geosite:cn` (§8.2).
2. **Add the user.** `mooringctl user add`, typing the user's label at its prompt (never as an argument, which the shell history keeps), with the client line CFM 0.5 (`Cfm05`). A user without an alias gets one with `user alias <uid>`: files are named after the alias, never the label.
3. **Hand over the two documents:** [user-onboarding.md](user-onboarding.md) and [user-agreement.md](user-agreement.md).
   - Send the text from each title on. The operator notes in the comment at the top are not for users.
   - They hold no secrets, but they describe the service, so they never cross WeChat, QQ or any other mainland-China service, encrypted or not. Hand them over in person by AirDrop (never on paper, which a search finds), or put them in an encrypted image of their own, made and sent as in section 4 with its own passphrase.
4. **Get the user's acceptance on the call.**
   - On a FaceTime Audio call, the user says 「我已阅读并同意《Mooring 使用约定》第 N 版」, where N is the revision the build ships (`AgreementVersion::CURRENT`, now 1).
   - Then run `mooringctl user agree <uid>`. It records the revision and the UTC day, and takes neither as an argument. It is a bookkeeping record: it keeps the generation, so it needs no apply (§7).
5. **Apply in the window.** `user add` changed the configuration, so every node the user holds needs `node apply` before the export. The apply restarts the engines and drops every user's connections for a few seconds, so let the nightly job apply it at 03:20 China time (§13.6), or run `node apply` yourself between 03:00 and 03:45 China time, before the nodes' 04:00 reboot. Deliver after the apply.

## 2. Export

```
mooringctl user export <uid> --format singbox --out <exports>/<alias>.json
```

- **Format.** Use `--format clash` only if the user asks for YAML.
- **Names.** Name the file, the image and the volume after the user's alias. Never use the label, "Mooring", "VPN" or "proxy".

Refusals and what to do about each:

| Refusal | Meaning | Action |
|---|---|---|
| `UserNotActive` | The user is suspended, being revoked or revoked | Resume the user, or stop: a revoked user gets nothing |
| `AgreementNotAccepted` | No agreement record, or a record of another revision; the message names the recorded revision | Hand over the current agreement text, take the acceptance on the call and run `user agree`. A record of a newer revision than the build ships means the build is older than the one that recorded it: upgrade, never record a lower revision |
| `CapabilityUnsupported` | The user's client line does not accept a capability on the profile | Fix the user's client profile |
| `NothingToExport` | The user holds no credentials | Add the user to a node |
| `NodeNotApplied` | A node in the file has not confirmed the current generation | `node apply` that node, in the window |
| `CertNotCurrent` | A node's certificate is not valid now, with one day of margin | Check the Mac's clock first: `sntp time.apple.com` prints its offset. Only if the clock is right, rotate the node (§13.4) |
| Any other `Cert…` | A node's certificate fails the export's checks. The certificate is never re-issued | Rotate the node (§13.4) |
| `Secret` | A credential is missing from the Keychain | `mooringctl doctor`, then `user reissue` if needed |
| `Model`, `InvalidTag`, `Encode` | An unknown user, or a defect in Mooring | Check the user id; otherwise stop and record the error: it is a bug, not an operating state |

## 3. Channel A: in person

- **AirDrop:** with "Contacts Only" on the user's Mac. The file lands in the user's Downloads folder.
- **USB stick:** carry the encrypted image of section 4, never the plain file: erasing flash memory does not reliably remove a file.
- Watch the import happen.

## 4. Channel B: encrypted disk image

1. Draw the passphrase first: six words at random from the EFF long word list (7,776 words, about 77 bits), in lowercase and separated by single spaces.
   - Draw them with five dice per word, or with a cryptographically secure generator. Never let a person choose them.
   - Use a new passphrase for every image.
   - Never write the passphrase in any message, note or file that leaves the Mac.
2. Put only the file in an empty folder under `<exports>`.
3. Create the image:
   ```
   hdiutil create -encryption AES-256 -srcfolder <folder> -volname <alias> <exports>/<alias>.dmg
   ```
   Type the passphrase twice at the prompt. Never use `-passphrase`, which would put the passphrase in the process list and the shell history.
4. Send the image. Whatever server it crosses may keep it, so only the passphrase protects it, and any channel may carry it except those that tie it to the user's real-name identity in mainland China: never WeChat, QQ (QQ Mail included), another mainland-China mail or cloud service, or iMessage to a mainland-China Apple ID. Send no words about the service with it.
5. On a FaceTime Audio call, say the words once, and spell them if needed.
   - Never use a WeChat or QQ call, or a carrier call into China.
   - Stay on the call while the user mounts the image and imports the file. The user must not tick "Remember password in my keychain".

## 5. Never

- Screenshots, photos or QR images of an export.
- The file's text, or any URI, pasted into a chat, a mail or a document.
- iMessage to a mainland-China Apple ID, for anything about the service. GCBD keeps Messages in iCloud for such accounts.
- The plain file over the internet: AirDrop in person is the only network that carries it.
- The documents, or any words about the service, over WeChat, QQ or another mainland-China service. Messages there arrange a call and nothing else.

## 6. After import

1. **The user's side.**
   - The user checks that CFM's credentials dialog shows every credential stored in the Keychain vault.
   - The user then ejects the image, deletes the file and the image, empties the Trash, and deletes the message that carried the image.
2. **The operator's side.**
   - Delete the file, the image and the folder under `<exports>`.
   - Confirm the first bytes on the node in the console's rotation tracker (§15.3).

## 7. Re-delivery

Re-deliver by the same channels in four cases:
- after a rotation (§13.4);
- after a `user reissue` (section 8);
- after a new REALITY target (§11.7);
- when the standby arrives (M9).

A new agreement revision changes no byte of a file: it only gates the next export, so it needs no re-delivery.

There is no subscription (F11). The user deletes the old profile after importing the new one.

In the M8 pilot there is one node, so a blocked node means a rotation and a new file for every user. Follow §13.4's single-node order: the new node is applied and every file re-exported before the blocked node is retired.

## 8. Leaks and seizures

| What happened | Response |
|---|---|
| A copy outside these rules (a file kept, a copy in a chat, a paste, a screenshot), a lost device, or the file handed to someone else, or the user cannot tell whether it was | `mooringctl user reissue <uid>`: new credentials on every node the user holds. Then `node apply` each of those nodes at once, outside the window if need be, because the old credentials work until the nodes apply. Then deliver a new file to that user alone (sections 2–6). The nodes' addresses stay known to whoever holds the copy: a later block is handled by rotation (§13.4) as usual |
| Someone asked the user for the file, and the user refused | Nothing to rotate. Remind the user of clause 2 of the agreement |
| A device seized or inspected by someone else, or the user under pressure | Revoke the user (§13.5), then rotate every node the user held (§13.4), and deliver new files to every other user on those nodes. Serving the person again is a new admission: `user add` and a new acceptance |

Record nothing about the incident itself (what happened, where, to whom) in Mooring, a note or a message: the commands record the changes they make.

## 9. Support

- The support channel is a FaceTime Audio call, or a meeting in person.
- In WeChat, QQ or any other chat, the user and the operator only arrange a call: no words about the service, no file, no screenshot.
- On the call, ask what the agreement's clause 5 asks for: when it started, which network, and whether every node fails.

## 10. Requests about the user's records

On the user's request, tell the user what is held about them (clause 4 of the agreement): on the operator's Mac the label, the alias, the client line, the policy, the usage history and totals, the last-active time, the status changes, the journal's operator actions that name the user (exports, reissues) and the acceptance; on each node the usage bins (48 hours), the monthly totals (until 7 days after the month), the last-active time and the user's row in the Mac report. A user who leaves may ask for the Mac's records to be deleted at once: revoke the user, then `user forget <uid>` (M5) once the user is `Revoked`, instead of waiting for the 13-month rule (§15.7). The nodes' records expire on their own schedule (§11.5); tell the user so.
