<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Runbook: delivering a user's configuration

This runbook is for the operator. It covers a user's first configuration, every later one, and what to do after a leak or a seizure.

The rules come from design §9.2, §9.4, §9.5, §13.4, §13.5 and §13.6, and from decisions F9–F11. The operator delegated those decisions to the recommended default on 2026-10-15 (§20.2), and revised them on 2026-11-06 with revision 2 of the agreement:
- configurations reach users through the user portal, by subscription link or download (section 11);
- every user has a portal account and pays there;
- a file by the channels of sections 2 to 6 is the backup for when the portal cannot be reached.

Users are asked to accept revision 2 only once payment is built (the operator notes of `user-agreement.md`).

**What exists today.**
- `hdiutil`, `tmutil` and `mooringctl user add | alias | agree | export | export-profiles` and `mooringctl portal export` (the `mooringctl` ones since 2026-10-18, the portal's since 2026-11-06, in the development build, which keeps its secrets in the login keychain until M5's data-protection keychain; they need the state that `exit init` will create).
- The portal's commands (`mooring-portal bind | bound-users | import | import-profiles | delete-account | ban | unban`) run on the portal's host.

**What is still to come.**
- The other `mooringctl` commands below (`user reissue`, `node apply`, `apply`, `doctor`, `user forget`) arrive in M5, and so does the console's rotation tracker.
- The payment pull, which grants what users buy at the portal and is how an outage is made up (section 9), arrives with the payment work.

Until then this runbook is the procedure they will follow.

## 0. Once, before the first user

**On the operator's Mac.** Make one folder for exports, outside iCloud Drive, Desktop and Documents, and keep it out of Time Machine, so that no backup keeps a file after it is deleted (design §12):

```
mkdir -m 700 <exports>
tmutil addexclusion <exports>
tmutil isexcluded <exports>
```

The last command must print `[Excluded]`.

Make a second folder the same way for the ban records (section 10). A ban record is deleted when the service ends, or at once if its ban was a mistake, so no backup may keep a copy:

```
mkdir -m 700 <bans>
tmutil addexclusion <bans>
tmutil isexcluded <bans>
```

**On the portal's host.** Clause 4 of the agreement promises these, so the portal opens to users only when they hold:
- The portal runs on a UK VPS of its own, never on a node or on the Mac.
- TLS ends on that host, at the reverse proxy in front of the portal (the portal's README, "部署前提"): no relay or CDN between the user and that host decrypts the traffic.
- The reverse proxy keeps no access log, compresses nothing under `/sub/`, and passes the client address as the portal's README says. The portal itself keeps client addresses only in memory.
- No backup or host snapshot of the portal's database outlives what clause 4 promises. Keep none, and turn off the provider's automatic snapshots of that host, or keep only one that is deleted on the same schedule. Its database and any backup hold every bound user's credentials: keep them as the export files are kept.
- Deploy the portal at its commit `e0604f2` or a later one, the first that does what clause 4 says of its deletions and its ban list: it erases what it deletes (since `f87ddb8`), and its ban list keeps slow Argon2id digests of the email, not fast ones (since `e0604f2`). Start it on a database it creates: a ban recorded by an earlier commit would not match. Change the database only with the portal's own commands, never with `sqlite3`.
  - A command that deletes or overwrites rows may report that the database stayed busy. Its change is then done but not erased: run `mooring-portal --db <file> erase-deleted` at once.
- Run the portal's commands by hand. Their output names account numbers and Mooring ids, so keep it out of cron jobs, systemd units and mail. The portal's own log names no account (`f87ddb8`).
- The operator's Stripe account accepts bank cards only, never Alipay or WeChat Pay: their merchant rules prohibit VPN and proxy services (Stripe's Alipay terms, stripe.com/legal/alipay), and their records are tied to the user's real name. Its payment links offer the card alone, with Apple Pay, Google Pay and Link off: clause 3's card check needs the card's own fingerprint, and a wallet payment may carry its token's instead (Stripe's API reference for card.fingerprint).
- It shows users a business name and a statement descriptor that say nothing about the service: they appear in the user's bank records.

## 1. Before the first configuration

1. **The user's CFM.**
   - The user runs CFM on an Apple-silicon Mac with macOS 15 or later: CFM is arm64 only from 15.0.
   - The CFM build must be a 0.5-line release that has the mainland China direct switch (F10): CFM 0.5.0 (build 50030, tag `v0.5.0`, released 2026-10-18) or a later 0.5.x. The switch is `d828f92`; 0.5.0 is the first release with it.
   - Do not deliver a configuration to an older CFM. Without the switch, mainland sites fail, because the nodes deny `geoip:cn` and `geosite:cn` (§8.2).
2. **Add the user.** First compare the person with the ban records (section 10): their name, and the phone number or Apple ID they call from. On any likeness, stop until you have checked. Then `mooringctl user add`, typing the user's label at its prompt (never as an argument, which the shell history keeps), with the client line CFM 0.5 (`Cfm05`). A user without an alias gets one with `user alias <uid>`: files are named after the alias, never the label.
3. **Hand over the two documents:** [user-onboarding.md](user-onboarding.md) and [user-agreement.md](user-agreement.md).
   - Send the text from each title on. The operator notes in the comment at the top are not for users.
   - They hold no secrets, but they describe the service, so they never cross WeChat, QQ or any other mainland-China service, encrypted or not. Hand them over in person by AirDrop (never on paper, which a search finds), or put them in an encrypted image of their own, made and sent as in section 4 with its own passphrase.
   - Say the portal's address on a FaceTime Audio call. Never write it in a message.
4. **Get the user's acceptance on the call.**
   - On a FaceTime Audio call, the user says 「我已阅读并同意《Mooring 使用约定》第 N 版」, where N is the revision the build ships (`AgreementVersion::CURRENT`, now 2).
   - Then run `mooringctl user agree <uid>`. It records the revision and the UTC day, and takes neither as an argument. It is a bookkeeping record: it keeps the generation, so it needs no apply (§7).
5. **Bind the portal account.** The user registers at the portal and reads out, on the call, the account number (账号编号) its 「账户」 page shows. On the portal's host, run `mooring-portal --db <file> bind --account <number> --user <uid>`. Bind by that number, never by an email address: the portal does not verify addresses (its `docs/security.md` §2).
6. **Payment.** The user buys a month or a traffic pack at the portal, by bank card. The payment pull grants it (with the payment work), except a payment by a card the ban list holds: that one grants nothing, and you refund it in the Stripe Dashboard (clause 3), since the portal holds no key that can refund. If it started an auto-renewing month, also cancel that subscription and delete the saved card. Compare the user's payments with the banned users' in the Stripe Dashboard (card, IP address, location, device), and copy nothing of a new user's payments out of Stripe. A payment made through the service reaches Stripe from the line's own address, and every user pays from Safari on a Mac (the guide, section 2), so neither is a likeness.
7. **Apply in the window.** `user add` changed the configuration, so every node the user holds needs `node apply` before the export. The apply restarts the engines and drops every user's connections for a few seconds, so run `node apply` yourself between 03:00 and 03:45 China time (19:00 to 19:45 UTC), before the nodes' 04:00 reboot; the nightly job that is to do it at 03:20 (§13.6) is not built yet. While no user is connected, as for the first users before the pilot starts, apply at any time. After the apply, export the bundle and the snapshot and import them at the portal (section 11).

## 2. Export a file (the backup)

A file goes to a user only when the portal cannot be reached and the user needs a new configuration.

```
mooringctl user export <uid> --format singbox --out <exports>/<alias>.json
```

- **Format.** Use `--format clash` only if the user asks for YAML.
- **Names.** Name the file, the image and the volume after the user's alias. Never use the label, "Mooring", "VPN" or "proxy".
- **The file.** The command creates it with mode 0600 and never overwrites a file. It warns, and writes the file all the same, when the folder is in iCloud Drive, another cloud folder, the Desktop or Documents, or when Time Machine backs it up: move the file and fix the folder (section 0) before going on.

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
| "reading the user's secrets from the keychain failed" (or `Secret`) | A credential is missing from the Keychain, or the Keychain refused | `mooringctl doctor`, then `user reissue` if needed |
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

- Screenshots, photos or QR images of an export, or of a subscription link.
- The file's text, a subscription link or any other URI pasted into a chat, a mail or a document.
- iMessage to a mainland-China Apple ID, for anything about the service. GCBD keeps Messages in iCloud for such accounts.
- The plain file over the internet: AirDrop in person is the only network that carries it. The profile bundle goes to the portal's host only over an encrypted connection (section 11).
- The documents, the portal's address, an account number or any words about the service over WeChat, QQ or another mainland-China service. Messages there arrange a call and nothing else.

## 6. After import

1. **The user's side.**
   - The user checks that CFM's credentials dialog shows every credential stored in the Keychain vault.
   - For a file, the user then ejects the image, deletes the file and the image, empties the Trash, and deletes the message that carried the image. A file downloaded from the portal is deleted the same way.
2. **The operator's side.**
   - Delete the file, the image and the folder under `<exports>`. Delete the profile bundle and the snapshot on both machines once they are imported.
   - Confirm the first bytes on the node in the console's rotation tracker (§15.3).

## 7. New configurations

A user needs a new configuration in four cases:
- after a rotation (§13.4);
- after a `user reissue` (section 8);
- after a new REALITY target (§11.7);
- when the standby arrives (M9).

Export the bundle and import it at the portal (section 11). Then tell each user concerned, on a call, to choose 「更新」 for the profile in CFM, or to download the file again from the portal and import it. CFM does not update a profile by itself. Only when the portal cannot be reached, deliver a file by sections 2 to 6; the user deletes the old profile after importing the new one.

A new agreement revision changes no byte of a configuration: it only gates the next export, so it needs no new one. At the portal a user who has not accepted it is withheld until they do (section 11).

In the M8 pilot there is one node, so a blocked node means a rotation and a new configuration for every user. Follow §13.4's single-node order: the new node is applied and every user's configuration exported (the bundle imported at the portal) before the blocked node is retired.

## 8. Leaks and seizures

| What happened | Response |
|---|---|
| A copy outside these rules (a file kept, a copy in a chat, a paste, a screenshot), a lost device, or the file handed to someone else, or the user cannot tell whether it was | `mooringctl user reissue <uid>`: new credentials on every node the user holds. Then `node apply` each of those nodes at once, outside the window if need be, because the old credentials work until the nodes apply. Then export the bundle, import it at the portal, and have that user choose 「更新」 (section 7). The nodes' addresses stay known to whoever holds the copy: a later block is handled by rotation (§13.4) as usual |
| A subscription link that may have leaked: sent, pasted, shown on a screen to someone, photographed, or the user cannot tell | The user regenerates the link at the portal (「重新生成」), or disables it (「停用链接」), at once. A paused link offers only 「停用链接」: the user makes a new one once served again. Whoever had the link may already hold the configuration, so continue as for a copy above. The user imports the new link into CFM and deletes the old profile |
| The user's portal password may have leaked | The user changes it at the portal. That ends every other session and disables the link. Whoever held the password could have generated a link, so continue as for a leaked link |
| The portal's host compromised, or its database or a backup leaked | Every bound user's credentials and the nodes' addresses are out. `user reissue` every user, `node apply` every node at once, export the bundle and import it at a host you trust again, and have every user generate a new link and import it (or download the file again). Rotate the nodes when they are blocked (§13.4) |
| Someone asked the user for the file or the link, and the user refused | Nothing to rotate. Remind the user of clause 2 of the agreement |
| A device seized or inspected by someone else, or the user under pressure | Revoke the user (§13.5) and delete their portal account (section 10). Then rotate every node the user held (§13.4), and update every other user on those nodes (section 7). Serving the person again is a new admission: `user add` and a new acceptance |
| You established that the user used the service for unlawful activity (clause 3) | Ban, as section 10 says: revoke the user (§13.5), write the ban record, then ban the portal account. Nothing is refunded. Rotate the nodes the user held if the activity may draw attention to them (§13.4) |

Record nothing about the incident itself (what happened, where, to whom) in Mooring, a note or a message: the commands record the changes they make.

## 9. Support

- The support channel is a FaceTime Audio call, or a meeting in person.
- In WeChat, QQ or any other chat, the user and the operator only arrange a call: no words about the service, no file, no link, no screenshot.
- On the call, ask what the agreement's clause 5 asks for: when it started, which network, and whether every node fails.
- **Outages (clause 1).** Make up an outage when every node failed for the user, or every user was paused, for 8 hours or more, for a reason on the operator's side.
  - The reasons that count: the Mac, the line, a node, a block (one on the user's carrier or region only counts too), or the line's shared cap.
  - Make it up with more service time than the outage, or extra traffic, granted through the payment pull's grants (with the payment work).
  - Refund by the outage's time, through Stripe, only if the user insists.
- **Refunds.** When the service ends, refund every user's unused days. A refund goes back to the card that paid. Once that card can take no refund, make it up in time or traffic instead, except for a payment by a card on the ban list, which is only ever refunded (section 1, step 6). A ban found to be a mistake is made up as section 10 says. Nothing else is compensated or refunded.
- **Auto-renewal.** The user cancels it at the portal (to be built with payment), or asks on a call and you cancel it in the Stripe Dashboard. The period already paid runs to its end.

## 10. Requests about the user's records

On the user's request, tell the user what is held about them (clause 4 of the agreement):
- **On the operator's Mac:** the label, the alias, the client line, the policy, the usage history and totals, the last-active time, the status changes, the journal's operator actions that name the user (exports, reissues), the payments pulled from the portal (with the payment work) and the acceptance.
- **On each node:** the usage bins (48 hours), the monthly totals (until 7 days after the month), the last-active time and the user's row in the Mac report.
- **At the portal:** the account (number, email, password hash, the registration and password-change times), the sessions (token digests, login and expiry times), the link's token digest and its time, the binding and its time, the latest snapshot record, the CFM profile, and the orders (with the payment work). After a ban, only the email's digest, the Stripe fingerprints of the cards the user paid with (with the payment work) and the ban's time, until the service ends.
- **After a ban, in the ban record on the operator's Mac:** the label, the phone number or Apple ID of the FaceTime calls, the ban's day, the copies of the user's hourly and daily usage and of their payments, and what the Stripe Dashboard showed of those payments (IP address, location, device) (below).
- **On the operator's phone and Mac:** FaceTime's call history with the user (number or Apple ID, call times), until the revocation.
- **At Stripe:** the payments, with what the payment page collected (email, cardholder name), the card's brand, last four digits, expiry and country, and the IP address, location and device data Stripe's fraud checks gather; the saved card while auto-renewal runs.

**Revocation for non-payment.** Revoke a user whose service expired three months before and was not renewed (clause 6 of the agreement), by hand until Mooring does it, then delete as below.

**Deletion.**
- When the user is revoked, for leaving or otherwise, first finish what the portal's account still serves (the portal's `docs/payments.md`, "删除账号"):
  - cancel the user's auto-renewal in the Stripe Dashboard;
  - settle any compensation or refund;
  - let the payment pull take the account's paid orders.
- Then delete the user's saved card at Stripe, your FaceTime call history with them on your phone and Mac (clause 4; an earlier backup keeps its copy until it is deleted or overwritten, as clause 4 says), and their portal account on its host: `mooring-portal --db <file> delete-account --account <number>`. It removes the account with its sessions, binding, snapshot record, profile and link, and the orders go with it.
- **A ban** (clause 3): the same steps, but once the payment pull has taken the account's paid orders, write the ban record (below). Then end with `mooring-portal --db <file> ban --account <number>` instead of `delete-account`, giving it the fingerprints of the cards the account paid with, read in the Stripe Dashboard (with the payment work).
  - It deletes the account as `delete-account` does, and keeps, until the service ends, the digest of the account's email and the ban's time, so that email cannot register again. With the payment work it is also to keep the cards' fingerprints. A later payment by one of those cards grants nothing: refund it in the Stripe Dashboard. Clause 4 says so.
  - An email stops only that email, and a card only that card: what keeps a banned person out is the binding by account number on a call (section 1), with the ban records checked before it.
  - Mooring's revocation records no reason, so the ban at the portal is a step of its own.
  - A ban found to be a mistake is undone (clauses 1 and 3):
    - ask the user for their login email on a call, since the ban record does not hold it, then run `unban --email <address>`, which drops the email's digest, and the cards' fingerprints too once they exist;
    - delete the ban record;
    - the deleted account does not come back, so the user joins again as a new user (section 1);
    - make up the days unused at the ban, or refund them if the user insists.
- **The ban record** (clauses 3 and 4).
  - Keep it in `<bans>` (section 0) as plain files, never in Contacts, Notes or any other synced app, until the service ends. Then delete it, with the portal's ban list.
  - It holds:
    - the user's label;
    - the phone number or Apple ID of the FaceTime calls;
    - the ban's day;
    - copies of what the Mac holds of the user's hourly and daily usage (bytes by node and protocol) and of their payments, taken after the last payment pull. No command prints one user's usage yet; one is to be built before the first ban.
    - what the Stripe Dashboard shows of those payments: IP address, location and device. Each payment carries the portal's order number, which Stripe keeps as the Checkout Session's `client_reference_id` (the portal's `docs/payments.md` §2), so they can still be found once the portal's orders are gone.
  - Never write in it the portal login email: that would undo the portal's digest. When the FaceTime Apple ID is that same address, record it as the FaceTime contact all the same.
  - Never write in it what happened or any evidence (section 8), links or credentials.
- **Recognising a banned person** (clause 4). Compare every new user with the ban records:
  - before `user add` (section 1);
  - at their payments: the card, and the IP address, location and device the Stripe Dashboard shows;
  - while they are served: their hourly and daily usage and payments, against the copies.

  The line's own address and Safari on a Mac are no likeness (section 1, step 6). A likeness is a reason to check, never a ban by itself: ban only once you have confirmed that it is the same person.
- A user who leaves may ask for the Mac's records to be deleted at once: revoke the user, then `user forget <uid>` (M5) once the user is `Revoked`, instead of waiting for the 13-month rule (§15.7). A ban record stays (clause 4).
- The nodes' records expire on their own schedule (§11.5), and Stripe keeps its payment records by its own rules; tell the user so.

## 11. The user portal

Design §9.5 and `docs/portal-contract.md` describe the portal's two files. Revision 2 of the agreement covers the portal, so both commands run, and a user's data goes to the portal only once the user has accepted it.

- **Name the bound users.** `mooring-portal --db <file> bound-users` on the portal's host prints every user bound to a portal account as one line of `--user <uid>` arguments, in id order; pass that line to both commands below, leaving out of the snapshot's list a user who has not accepted the current revision yet (the profile bundle, below). Every user is bound once registered (section 1); a user not yet bound is not named, and nothing about them goes to the portal.
- **The snapshot.** `mooringctl portal export --user <uid> [--user <uid>...] --out <folder>/snapshot.json` writes the snapshot of the users named; it holds no credentials. Import it with `mooring-portal import` on the portal's host. Export it again whenever a user's status, quota or expiry changes, and often enough that users see their usage: each import replaces the last.
- **The profile bundle.** `mooringctl user export-profiles --user <uid> [--user <uid>...] --out <folder>/profiles.json` writes the profile bundle of the users named, which holds the credentials of every one delivered.
  - Write it into the folder of section 0, copy it to the portal's host over an encrypted connection, import it with `mooring-portal import-profiles`, and delete it on both machines.
  - The command refuses a list with an id no user has, or a user twice, and writes nothing. The portal refuses a bundle that leaves out a bound user and changes nothing; export again with every bound user named. Unbind an account only when it is no longer to be served, since unbinding deletes its profile and its link.
  - A user named who is suspended, being revoked, revoked, or has not accepted the current revision is withheld, and the command names each with the reason and what the import does to their subscription link. On import a withheld user has no profile at the portal. Their link follows clause 5 of revision 2 (the operator's decision, 2026-11-06), as the portal's import does since its commit `120ca8a`:
    - A suspension, whatever its reason (quota, expiry, review or yours), and a missing acceptance only pause the link. Once you resume the user, or they accept, the next bundle delivers them again and the same link works: no new link is generated, and the user chooses 「更新」 in CFM. Mooring does not yet lift a suspension for quota at the next billing cycle by itself (M5's apply will): resume the user, then export and import the bundle.
    - So after a new agreement revision the bundle need not wait until every bound user has accepted it: those who have not are withheld, and their links pause until they accept. The snapshot refuses a user named without the acceptance, so leave those users out of `portal export`'s list until they accept; the portal keeps their last snapshot meanwhile.
    - A revocation ends the link for good. For a ban for illegal use, revoke the user here and ban the account at the portal, a separate step there, which also bars it from registering again. The portal never takes a revocation for a ban, since a user who leaves is revoked too.
- **When to export the bundle again:** after every change that changes a user's configuration (section 7), and whenever a user is bound or unbound at the portal, added (once every node is applied), suspended, resumed, revoked, or accepts a new revision. CFM does not update a profile by itself: the user chooses 「更新」 for it (section 7).
- **Payment.** Users buy months and traffic packs at the portal through Stripe, by bank card. The payment pull grants them to the user on the Mac, and the next snapshot shows the new expiry and quota (with the payment work). A month runs to its expiry with the billing cycle's quota; renewing early moves the expiry, not the quota. A user paused for quota resumes on a traffic pack (with the payment work), or at the next billing cycle once M5's apply lifts the suspension; until then, resume them by hand (above).
