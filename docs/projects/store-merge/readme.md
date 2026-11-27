---
status: completed
priority: now
---

# Mergeable store

Every entry records when it last changed and keeps its earlier secrets, a removed entry leaves a dated marker, and two copies of the store merge into one, entry by entry, with the same result on every machine and without losing a secret.

## 1. Problem

The store is one text document inside one age file, and a save replaces the whole file. When two Macs save copies of the store that each changed, nothing can combine them: the sync service keeps one file and drops or sets aside the other, and every change in the dropped copy is lost. So the README says to edit on one machine at a time.

The vault-key plan, which comes next, writes every save as a new file and never modifies a file once written, so that sync can never overwrite anything. That design needs a way to combine the store files it finds into one store. This plan supplies it: store format 3 and a merge. It changes no file layout, and nothing calls the merge until the vault-key plan ships.

## 2. Solution

Store format 3 adds one line to every entry, `modified <milliseconds>`, the time it last changed, and password history: each entry keeps the secrets and setup keys it used to hold, each with the time it was replaced (§ 2.6). Removing an entry no longer drops it: it becomes a tombstone, the entry's name with its `modified` line and a `deleted` line, so a merge can tell "removed" from "never seen". `Store::merge` combines any number of stores by keeping, for each name, the version with the newest `modified`, and breaks a tie by comparing the two versions' text. The losing version's secret and setup key join the winner's history, so a merge never drops a secret. The merge gives the same result in any order and is unchanged by merging a store with itself, so two Macs that merge the same files always agree. Each change is stamped one millisecond past the newest stamp in the store it was made from, so a change made after seeing another always wins over it, even when the clocks disagree. Tombstones are dropped when a store is written once they are older than 120 days and older than every key the vault-key plan still holds. A tombstone keeps the removed entry's secrets for 30 days, so `rm` can be undone. multipass reads formats 1, 2, and 3, and writes format 3.

### 2.1 Store format 3

Each store format number names one text, defined in one plan:

| Header | Adds | Defined in |
| --- | --- | --- |
| `multipass 1` | Entries with `secret`, `username`, and `notes` | Before Projector; `Store::from_text` still reads it |
| `multipass 2` | The `otp` field | The one-time-passwords plan, § 2.4 |
| `multipass 3` | `modified`, tombstones, and history | This plan |
| `multipass 4` | The `passkey` field, on top of format 3 | The passkeys plan, § 2.2 |

```text
multipass 3
github.com
	modified 1764160000123
	secret hunter2
	username octocat
	previous-secret 1764160000123 hunter1
old-bank
	modified 1764160000456
	deleted
	previous-secret 1764160000456 correct horse battery staple
```

| Line | Rule |
| --- | --- |
| `modified <ms>` | Required, the first field line of every entry: milliseconds since the Unix epoch, in decimal, with no leading zeros. |
| `deleted` | Marks a tombstone. A tombstone holds `modified`, `deleted`, and history lines, and no other field. |
| `previous-secret <ms> <value>`, `previous-otp <ms> <value>` | An earlier secret or setup key, after the time it was replaced, which is never later than the entry's `modified`. The value is escaped like any other, and a `previous-otp` value must be a valid `otpauth://totp/` URI. Written newest first; read in any order, keeping each value once, at its latest time (§ 2.6). |
| Every other field | As in format 2. A live entry still needs a `secret`, an `otp`, or both. |

Entries read from format 1 or 2 get `modified 0`, so any later change wins over them, and two machines that upgrade the same store separately agree.

### 2.2 How a change is stamped

| Operation | What it records |
| --- | --- |
| `add`, `otp --set`, `otp --clear` | The new entry, with `modified` set to the stamp below, and the secret or setup key it replaced in its history, dated by that stamp |
| `rm` | A tombstone with the stamp below, holding the entry's secret, setup key, and history |
| `get`, `get --previous`, `history`, `list`, `otp` | Nothing; reading changes no stamp |

The stamp is `max(now, newest + 1)`, where `now` is the wall clock in milliseconds and `newest` is the largest `modified` in the store the change was made from, tombstones included. This is a hybrid logical clock with a single counter. When the result is more than a day ahead of `now`, because some machine's clock ran fast, multipass warns once with `a change in the store is dated in the future; check the clocks of the machines that sync it`, and still saves.

### 2.3 How stores merge

`Store::merge(&[Store]) -> Store` takes the union of the names. For each name it keeps the version, live entry or tombstone, with the largest `modified`. When two versions share the stamp, it keeps the one whose format 3 text, without the name line and the history lines, sorts last as bytes. When they are identical, either will do. The kept version's history is the union of every version's history, plus each version's own secret and setup key dated by that version's `modified`, with each value kept once, at its latest time, and the kept version's current values left out (§ 2.6).

That rule picks one version from a set, and takes a union for the history, so the merge is commutative, associative, and idempotent. Two Macs that merge the same files, in any order and any grouping, write the same store. A tombstone beats every older version, so a removal is not undone by a copy that still holds the entry, and the copy's secret joins the tombstone's history rather than being lost.

`names()` and `get` skip tombstones, so every command sees only live entries. `version(name)` returns a live entry or a tombstone with its history, for `history` and `get --previous`. There is no `get_mut`: every change goes through `insert` or `remove`, which take a stamp.

### 2.4 Dropping old tombstones

When a store is written, `Store::to_text(cutoffs)` leaves out tombstones whose `modified` is before `cutoffs.tombstones`. Without the vault-key plan, the cutoff is 120 days before `now`, from `Cutoffs::at(now)`. With it, the caller passes the earlier of that and the `created` time of the oldest key it knows. A key is retired at the first prompt after it expires, which can be long after day 21 when nobody prompts for weeks, and it stays usable for 90 days after that, so no fixed bound covers every store file a retired key can still open. Tying the cutoff to the oldest known key means a removal is never forgotten while a file that predates it can still be merged. A copy of the store that comes back after more than 120 days away, through some path other than that merge, can bring back an entry removed in the meantime, and the README states the limit.

`Cutoffs` holds two more stamps, both from `Cutoffs::at(now)`, and § 2.6 says why. A tombstone whose `modified` is before `cutoffs.removed_secrets`, 30 days before `now`, is written without its history lines, so its marker outlives the removed secrets. An entry's history keeps its newest 10 values of each kind, and every older one replaced at or after `cutoffs.history`, a year before `now`.

### 2.5 Changes by file

| File | Change |
| --- | --- |
| `src/store.rs` | `Store` maps each name to a `Version { modified: u64, entry: Option<Entry>, history: History }`, where `None` is a tombstone and `History` holds the earlier secrets and setup keys as `Previous { replaced, value }`. `insert` and `remove` take the stamp and record what they replace in the history, and `remove` leaves a tombstone. `get_mut` is gone and `version` is new. New `Store::stamp(now)`, `Store::merge`, `Store::newest`, `dated_in_future`, and `Cutoffs`. New `expire(cutoffs)` drops expired tombstones, removed secrets, and history; `to_text(cutoffs)` writes format 3 from an expired copy; `from_text` reads formats 1 to 3. `encrypt` and `save` take the cutoffs. `Error::UnsupportedFormat` names formats 1 to 3. |
| `src/main.rs` | Each saving command takes a stamp from the store it opened and passes it to `insert` or `remove`, prints the clock warning, and saves with `Cutoffs::at(now)`. Opening the store expires it with the same cutoffs. `otp --set` and `otp --clear` build the new entry and `insert` it. New `history <name>` and `get --previous <n>`, with a UTC date formatter. |
| `README.md` | A section on getting an earlier password back. The recovery example shows `multipass 3`, `modified`, history, and a tombstone. `rm` in the usage example says it is recoverable for 30 days. |
| `AGENTS.md` | The note about the store header's version mentions format 3, and that the merge must keep its laws with history included. |

### 2.6 Password history

Each entry keeps the secrets it used to hold, and the setup keys, each with the time it was replaced. The history lives inside the encrypted store, in the entry's `previous-secret` and `previous-otp` lines.

| Command | What it does |
| --- | --- |
| `multipass history <name>` | Prints when the entry changed, or `removed` and when, then one row per earlier value, such as `secret 1   2026-11-20 14:03:12 UTC`, numbered as `--previous` counts. It prints dates only, never a value. A stamp of 0, from a format 1 or 2 store, prints as `unknown`. |
| `multipass get <name> --previous <n>` | Prints the `n`th most recently replaced secret, counting from 1; with `--field otp`, the setup key. Works with `--clip`. `--previous` with `--field username` or `--field notes` is refused. |

`get --previous` and `history` also find a removed entry. An `n` past the end fails with `<name> has only 2 earlier secrets`, or `<name> has no earlier secret`, which name a count and never a value. `n` must be 1 or more.

1. **What joins the history.** `add --force` adds the secret it replaces; `otp --set --force` and `otp --clear` add the setup key they replace. `rm` keeps the entry's secret and setup key in the tombstone's history. A later `add` of the same name keeps that history. A value that becomes current again leaves the history, because you already have it, and each value appears once, at its latest time.
2. **What a merge adds.** The losing version's secret and setup key join the winner's history, dated by the losing version's own `modified`, never by the winner's, so the result does not depend on the order or grouping of the merge. A version only ever holds history dated at or before its `modified`, which `from_text` enforces, so each value's latest time is the same however the stores are combined.
3. **What is kept.** When the store is written, an entry keeps its newest 10 earlier secrets, or every one replaced in the past year, whichever keeps more, and the same for setup keys. A tombstone keeps the removed secrets for 30 days after the removal and is then written without them, while its marker stays for the 120 days of § 2.4.

Pruning happens in `Store::expire(cutoffs)`, against `now`, and never in the merge. The merge is then a pure union, so its laws hold exactly. `to_text` expires a copy of the store before writing it, and the CLI expires the store as it opens it, so no command shows or reuses a value the next write would drop: after 30 days `history` and `get --previous` no longer find a removed secret, even in a file not written since. `insert` over a tombstone whose 30 days have passed by the new stamp also leaves its history behind, so a name added again after the 30 days never takes back the removed secrets. A value pruned by one Mac can come back in memory when an older copy is merged, so a caller that merges expires each store it opens before the merge, and `to_text` drops anything left before it is written.

## 3. Why this design

- **A stamp per entry, not per store.** Two Macs usually change different entries. A stamp per entry lets both changes survive, where a stamp on the whole store would make one Mac's save discard the other's.
- **Tombstones.** Without a marker, a merge cannot tell an entry one Mac removed from one the other Mac added, and the removed entry would come back.
- **One counter past the newest stamp.** Plain wall-clock time would let a Mac whose clock runs slow lose to an older change it had already seen. Taking `max(now, newest + 1)` orders every change after the changes it saw, and a full hybrid logical clock, with a separate counter field, buys nothing more for one user's handful of machines.
- **Ties broken by content.** The tie-break needs no device identity to store or sync, and it is deterministic, which is what makes every Mac write the same merged store.
- **The risk this leaves.** Two changes to the same entry made on two Macs, each before seeing the other, are decided by their clocks: the later stamp wins, and the other change is lost. A Mac with a clock far ahead wins such contests until real time catches up. That is the README's rule, "edits to different entries merge; the newer edit to the same entry wins", and the warning in § 2.2 flags a clock that is badly off.
- **120 days for tombstones, or longer while an old key remains.** A fixed 120 days covers sync delays, and the vault-key plan extends it while it still holds a key that could open an older store file, since a key can be retired late. The store still stops growing once old keys age out.
- **History, so a merge never drops a secret.** Newest-wins alone loses the other change when two Macs edit one entry before seeing each other's edit, and a lost password can lock you out of the account. Keeping the losing secret as history makes that loss recoverable, and the same history answers "what was my old password" after a deliberate change. Only secrets and setup keys are kept, because a lost username or note can be retyped.
- **Losing values dated by their own stamp.** Dating a losing value by the winner's stamp would give it a different date depending on which stores merged first, so two Macs could write different stores. The losing version's own `modified` is the same in every order.
- **Ten, or a year.** Ten values cover rotating a password several times in a day; a year covers a password rotated monthly. Pruning at write time, rather than in the merge, keeps the merge a pure union.
- **Removed secrets for 30 days, the marker for 120.** The user chose to keep a removed entry's secrets so `rm` can be undone, like a "recently deleted" folder, for 30 days. The 120 days of § 2.4 exist so a removal reaches every copy of the store, which is a sync concern, not a recovery one, so the two clocks are separate. Erasing the secrets at once was rejected: a merge with any older copy of the store would bring the removed secret back into the tombstone's history, since the merge cannot tell a value the remover saw from one it did not. `rm --purge` was not wanted.
- **Its own plan.** The format and the merge are pure functions on store text, testable without files, keys, or sync. Keeping them apart from the vault-key plan's file handling keeps each plan small enough for one reviewer.

## 4. Acceptance criteria

| Do | Expect |
| --- | --- |
| `multipass list` on a format 2 store, then `multipass add x`, then `age -d` on the store | The store text starts `multipass 3`, every old entry has `modified 0`, and `x` has a current stamp |
| `multipass rm x`, then `age -d` on the store | `x` remains as a tombstone with `modified` and `deleted`, and `multipass list` does not show it |
| `multipass get x` after `rm x` | Fails with `no entry named x` |
| `multipass add x --force` with a new secret, then `multipass get x --previous 1` and `multipass history x` | Prints the old secret; `history` prints `changed` and `secret 1` with dates and no value |
| `multipass get x --previous 1` after `rm x` | Prints the removed secret, and `history x` starts `removed` |
| `multipass get x --previous 3` when `x` has two earlier secrets | Fails with `x has only 2 earlier secrets` |

Tests that must fail before the change and pass after it:

- **Merge laws**, over generated stores of a few entries with overlapping names, stamps, tombstones, and history: `merge([a, b])` equals `merge([b, a])`, `merge([merge([a, b]), c])` equals `merge([a, merge([b, c])])`, and `merge([a, a])` equals `a`. Catches a tie-break that depends on order, and a losing value dated by the winner's stamp, either of which would make two Macs write different stores.
- **The losing edit becomes history.** Two copies edit `x` to different secrets; the merge keeps the later one and holds the other and the original as history, in both orders. Catches a merge that drops a secret.
- **Concurrent changes.** A store copied twice, with `x` added in one and `y` in the other, merges to hold both. Catches a merge that keeps one copy whole.
- **Edit against removal.** `x` edited in one copy and removed in the other keeps whichever has the later stamp, in both orders. Catches a tombstone that always wins or always loses.
- **Stamps after skew.** In a store whose newest stamp is an hour ahead of `now`, the next change is stamped one millisecond past it, and the warning does not fire; a day and a minute ahead, it fires. Catches a slow clock that loses to a change it already saw.
- **Old tombstones** are dropped by `to_text(cutoffs)` a millisecond before the cutoff and kept at it, and a cutoff from an old key keeps a 200-day-old tombstone that 120 days alone would drop. Catches a store that grows forever, and one that forgets a removal while a file that predates it can still be merged.
- **Removed secrets** are kept by a tombstone removed exactly 30 days before `now` and dropped from one removed a millisecond earlier, whose marker stays. Catches an `rm` that cannot be undone, and one that never forgets. A name added again 30 days and a millisecond after the removal, with no write in between, starts with no history, and one added at exactly 30 days keeps the removed secret. Catches a removed secret that a re-add carries for another year. `expire` leaves the store `to_text` would write. Catches a read that shows a value the next write drops.
- **History pruning** keeps the newest 10 of 12 old values, and keeps an eleventh and twelfth value replaced within the year, the twelfth at the cutoff and not a millisecond before it. Catches unbounded history, and a year that drops recent values.
- **Replacing and removing** record the old secret and setup key, drop a value that becomes current again, and keep a removed entry's history when it is added again. `get --previous` counts from the most recent and names only counts in its errors, and `history` shows no value.
- **Formats 1 and 2** read with `modified 0` on every entry, and format 3 round-trips through `to_text` and `from_text`, including a tombstone. A format 3 entry without `modified`, or a tombstone with a `secret`, fails with its line number. Catches an old store that stops opening, and a damaged store that parses.

## 5. Cost

Each entry grows by one short line, and by one line per earlier value, at most 10 of each kind once they are a year old. A merge of a few stores of a few hundred entries is a handful of map operations, too small to measure beside scrypt.

## 6. Open questions

None. The user chose immutable files merged per entry, newest change wins, and tombstones that expire. They then chose password history as part of format 3, with a merge that keeps the losing version as history, and chose that a removed entry's secrets stay recoverable for 30 days, with no `rm --purge`.

## 7. Outcome

Shipped in one pull request: store format 3 with `modified`, tombstones, and password history (§ 2.6), `Store::merge`, the stamps and the clock warning, and the `history` and `get --previous` commands. Each row of § 4 was run by hand against a release build with `expect`, on a format 2 store that the reference `age` crate, version 0.12.1, encrypted; the same crate decrypted each store multipass wrote. The tests § 4 lists pass, and the merge-law test fails when a losing value is dated by the winner's stamp.

Two things differ from § 2.5 as first written. `to_text`, `encrypt`, and `save` take a `Cutoffs` value with three stamps rather than one cutoff, for the tombstone, removed-secret, and history limits. `get_mut` is gone, so every change takes a stamp. Nothing outside the tests calls `Store::merge` yet; the vault-key plan is its first caller.
