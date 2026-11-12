<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Runbook: revoking a user

This runbook is for the operator. It covers revoking a user on the Mac and the nodes, what the nightly apply job does by itself, and the steps at Stripe and the portal when a user leaves or stops paying.

The rules come from design §13.5, §13.6 and §15.7, and from clauses 4 and 6 of the agreement's revision 2 (#28, not in force yet). `mooringctl user revoke` exists since 2026-11-12 (M5, on the topic branch `lza/revoke-4052c8`; not merged or installed yet). `mooringctl` is the one inside the installed app (`delivery.md`, opening).

A revocation cannot be undone. Serving the person again is a new admission: `user add` and a new acceptance (`delivery.md`, section 1).

## 1. When

| Case | What to do |
|---|---|
| The user leaves (clause 6) | Sections 2 and 3 |
| The user's service expired three months ago and was not renewed (clause 6) | The apply job revokes them by itself, once the agreement they accepted provides for it (section 4); then section 3 |
| A breach of the agreement: a ban (clause 3) | Sections 2 and 3, with the portal's `ban` instead of `delete-account` |
| A device seized or inspected, or the user under pressure | Section 2 at once, then rotate every node the user held (`delivery.md`, section 8) |
| A copy leaked, without a seizure | Not a revocation: `user reissue` (`delivery.md`, section 8) |

## 2. On the Mac

1. Run `mooringctl user revoke <uid>`. It says what follows: the user's status and the nodes holding its credentials. It says that the revocation cannot be undone, and asks; `--yes` skips the question. It refuses an unknown user, and one already being revoked or revoked.
   - A user who holds credentials on no node is revoked at once. Go on to step 3.
   - Otherwise the user is now being revoked (`RevokePending`). From this configuration on no bundle, export or portal profile includes them. Each node still serves them from its last configuration until it applies the new one.
2. **Apply the nodes.** The nightly job applies them at 19:20 UTC. For a seizure, apply them at once with `mooringctl apply --now`, which applies every node behind, whatever the time. `mooringctl node apply <node>` applies one.

   After a node applies, Mooring records the revocation there, then deletes the user's credentials for that node from the keychain. With no node left, the user is revoked. Both commands print a line for each node:
   - `revocation committed on <node>: <uid>, now revoked; …`;
   - `revocation committed on <node>: <uid>, which still waits on <node> (…)`.

   The job's report lists, every night, each user still being revoked and what each node waits for:
   - **behind:** its next apply commits it;
   - **adopted:** its first `node apply` commits it;
   - **retiring:** its shutdown settles it;
   - **planned:** `node cancel` settles it, or its first apply;
   - **applied, not recorded yet:** its next `node apply` or the job's next run records it.
3. **The portal.** Export the portal's bundle again (`delivery.md`, section 11), so that the portal ends the user's subscription link for good.

**A node that cannot be reached** (lon1 while its SSH is down) keeps the user being revoked, and the job reports it every night. Until that node applies, it serves the user's credentials. When the user must lose access at once (a seizure), only the provider's console can stop the node, which stops it for every user. Apply it once it can be reached.

**When `node apply` ends with "<node> is applied, but N of the revocations it settled could not be recorded or left keychain items",** the lines above it name each:
- A record that failed is made by the next `node apply` of that node or the job's next run.
- A keychain item that could not be deleted is used by nothing any more. Any still there may be deleted by hand; the line names it.

The job does the same and exits 1.

**When the clock stepped back** (the job's report starts with `policy step not carried out: a suspension for quota is dated after now`), the job records no revocation, as it removes no user. A record dates the revocation, and the user's records go 13 months after that date. The report still lists what waits; the next run with a sane clock records it.

## 3. Leaving: Stripe and the portal

For a user who paid through the portal (clauses 4 and 6 of revision 2), after section 2:

1. In the Stripe Dashboard, **cancel the user's subscription** (auto-renewal), so that Stripe charges nothing more. Wait until Stripe has told the portal that the subscription ended.
2. Settle any compensation or refund that clause 1 gives.
3. **Let the daemon's payment pull take the account's paid orders.** A payment made after the revocation grants nothing: the pull holds it (`user_revoked`), and you refund it at Stripe (`console.md`, section 6).
4. In the Stripe Dashboard, **delete the card saved** for the customer.
5. On the portal's host, **delete the account:**
   ```
   mooring-portal --db <file> delete-account --account <number>
   ```
   It deletes the account with its sessions, binding, snapshot record, CFM profile, subscription link and orders. It refuses while Stripe may still charge a subscription of the account, or while an order is not settled (paid but not taken by Mooring yet, or awaiting a check), and says what to do first (the portal's `docs/payments.md`, section 2.8). For a ban, run the portal's `ban --account <number> [--card <fingerprint> …]` instead, which does not wait for those.
6. Delete your FaceTime call history with the user on your phone and Mac (clause 4).
7. **The Mac's records.** If the user asked for the Mac's records to go at once, run `mooringctl user forget <uid>` once the user is revoked (`console.md`, section 7). Otherwise the job removes them 13 months after the revocation.

Tell the user that the nodes' records expire on their own schedule (design §11.5), and that Stripe keeps its payment records by its own rules.

## 4. Revocation three months after expiry

Clause 6 says that a service expired for three months without renewal ends in revocation. The nightly job's policy step does it:
- **Who.** Each user suspended at expiry whose effective expiry is three calendar months or more before the run, to the second. The effective expiry is their own expiry, extended by every month they paid, as the console shows it. An expiry on 31 August falls due on 30 November at the same time.
- **Never:** a user you suspended, one suspended for an abuse review, or one suspended for quota. An active user whose expiry passed is suspended first, and revoked at a later run at the earliest.
- **Report.** `revoked <uid>: suspended at expiry since …, its service expired at … and was not renewed in three months`. The user then waits on its nodes as in section 2, and the job's own applies that night commit it where they reach. `apply.log` counts the revocations and names no user.

The job leaves the user suspended, and reports them instead, in three cases:
- **The agreement does not provide for it:** `not revoked: <uid>, …; the agreement it accepted does not provide for revoking it, so that is yours to decide`. Revision 1 has no such clause, so until the build that ships revision 2 (#28), every user due is reported so. Revoke them yourself (section 2) only if the agreement they accepted allows it.
- **The payment pull is behind:** `not revoked yet: <uid>, …; that fell due at …, and the payment pull has not succeeded since`. A renewal paid by then may not have reached Mooring yet. A later run revokes them once a pull has succeeded. `mooringctl portal payments` shows the last pull that succeeded.
- **The clock stepped back:** the policy step is not carried out at all, so no one is revoked that night.

Then do section 3. A subscription that lapsed has ended already: delete the saved card and the account.
