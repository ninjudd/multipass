---
status: ready
priority: now
---

# Mergeable store

Every entry records when it last changed, a removed entry leaves a dated marker, and two copies of the store merge into one, entry by entry, with the same result on every machine.

## 1. Problem

The store is one text document inside one age file, and a save replaces the whole file. When two Macs save copies of the store that each changed, nothing can combine them: the sync service keeps one file and drops or sets aside the other, and every change in the dropped copy is lost. So the README says to edit on one machine at a time.

The vault-key plan, which comes next, writes every save as a new file and never modifies a file once written, so that sync can never overwrite anything. That design needs a way to combine the store files it finds into one store. This plan supplies it: store format 3 and a merge. It changes no file layout, and nothing calls the merge until the vault-key plan ships.

## 2. Solution

Store format 3 adds one line to every entry, `modified <milliseconds>`, the time it last changed. Removing an entry no longer drops it: it becomes a tombstone, the entry's name with its `modified` line and a `deleted` line, so a merge can tell "removed" from "never seen". `Store::merge` combines any number of stores by keeping, for each name, the version with the newest `modified`, and breaks a tie by comparing the two versions' text. The merge gives the same result in any order and is unchanged by merging a store with itself, so two Macs that merge the same files always agree. Each change is stamped one millisecond past the newest stamp in the store it was made from, so a change made after seeing another always wins over it, even when the clocks disagree. Tombstones are dropped when a store is written once they are older than 120 days and older than every key the vault-key plan still holds. multipass reads formats 1, 2, and 3, and writes format 3.

### 2.1 Store format 3

Each store format number names one text, defined in one plan:

| Header | Adds | Defined in |
| --- | --- | --- |
| `multipass 1` | Entries with `secret`, `username`, and `notes` | Before Projector; `Store::from_text` still reads it |
| `multipass 2` | The `otp` field | The one-time-passwords plan, § 2.4 |
| `multipass 3` | `modified` and tombstones | This plan |
| `multipass 4` | The `passkey` field, on top of format 3 | The passkeys plan, § 2.2 |

```text
multipass 3
github.com
	modified 1764160000123
	secret hunter2
	username octocat
old-bank
	modified 1764160000456
	deleted
```

| Line | Rule |
| --- | --- |
| `modified <ms>` | Required, the first field line of every entry: milliseconds since the Unix epoch, in decimal, with no leading zeros. |
| `deleted` | Marks a tombstone. A tombstone holds `modified` and `deleted` and no other field. |
| Every other field | As in format 2. A live entry still needs a `secret`, an `otp`, or both. |

Entries read from format 1 or 2 get `modified 0`, so any later change wins over them, and two machines that upgrade the same store separately agree.

### 2.2 How a change is stamped

| Operation | What it records |
| --- | --- |
| `add`, `otp --set`, `otp --clear` | The new entry, with `modified` set to the stamp below |
| `rm` | A tombstone with the stamp below |
| `get`, `list`, `otp` | Nothing; reading changes no stamp |

The stamp is `max(now, newest + 1)`, where `now` is the wall clock in milliseconds and `newest` is the largest `modified` in the store the change was made from, tombstones included. This is a hybrid logical clock with a single counter. When the result is more than a day ahead of `now`, because some machine's clock ran fast, multipass warns once with `a change in the store is dated in the future; check the clocks of the machines that sync it`, and still saves.

### 2.3 How stores merge

`Store::merge(&[Store]) -> Store` takes the union of the names. For each name it keeps the version, live entry or tombstone, with the largest `modified`. When two versions share the stamp, it keeps the one whose format 3 text, without the name line, sorts last as bytes. When they are identical, either will do.

That rule picks one version from a set, so the merge is commutative, associative, and idempotent. Two Macs that merge the same files, in any order and any grouping, write the same store. A tombstone beats every older version, so a removal is not undone by a copy that still holds the entry.

`names()`, `get`, and `get_mut` skip tombstones, so every command sees only live entries.

### 2.4 Dropping old tombstones

When a store is written, `Store::to_text(cutoff)` leaves out tombstones whose `modified` is before `cutoff`. Without the vault-key plan, the cutoff is 120 days before `now`. With it, the caller passes the earlier of that and the `created` time of the oldest key it knows. A key is retired at the first prompt after it expires, which can be long after day 21 when nobody prompts for weeks, and it stays usable for 90 days after that, so no fixed bound covers every store file a retired key can still open. Tying the cutoff to the oldest known key means a removal is never forgotten while a file that predates it can still be merged. A copy of the store that comes back after more than 120 days away, through some path other than that merge, can bring back an entry removed in the meantime, and the README states the limit.

### 2.5 Changes by file

| File | Change |
| --- | --- |
| `src/store.rs` | `Store` maps each name to a `Version { modified: u64, entry: Option<Entry> }`, where `None` is a tombstone. `insert` and `remove` take the stamp, and `remove` leaves a tombstone. New `Store::stamp(now)`, `Store::merge`, and `Store::newest`. `to_text(cutoff)` writes format 3 and drops tombstones before the cutoff; `from_text` reads formats 1 to 3. `Error::UnsupportedFormat` names formats 1 to 3. |
| `src/main.rs` | Each saving command takes a stamp from the store it opened and passes it to `insert` or `remove`, and prints the clock warning. |
| `README.md` | The recovery example shows `multipass 3`, `modified`, and a tombstone. |
| `AGENTS.md` | The note about the store header's version mentions format 3. |

## 3. Why this design

- **A stamp per entry, not per store.** Two Macs usually change different entries. A stamp per entry lets both changes survive, where a stamp on the whole store would make one Mac's save discard the other's.
- **Tombstones.** Without a marker, a merge cannot tell an entry one Mac removed from one the other Mac added, and the removed entry would come back.
- **One counter past the newest stamp.** Plain wall-clock time would let a Mac whose clock runs slow lose to an older change it had already seen. Taking `max(now, newest + 1)` orders every change after the changes it saw, and a full hybrid logical clock, with a separate counter field, buys nothing more for one user's handful of machines.
- **Ties broken by content.** The tie-break needs no device identity to store or sync, and it is deterministic, which is what makes every Mac write the same merged store.
- **The risk this leaves.** Two changes to the same entry made on two Macs, each before seeing the other, are decided by their clocks: the later stamp wins, and the other change is lost. A Mac with a clock far ahead wins such contests until real time catches up. That is the README's rule, "edits to different entries merge; the newer edit to the same entry wins", and the warning in § 2.2 flags a clock that is badly off.
- **120 days for tombstones, or longer while an old key remains.** A fixed 120 days covers sync delays, and the vault-key plan extends it while it still holds a key that could open an older store file, since a key can be retired late. The store still stops growing once old keys age out.
- **Its own plan.** The format and the merge are pure functions on store text, testable without files, keys, or sync. Keeping them apart from the vault-key plan's file handling keeps each plan small enough for one reviewer.

## 4. Acceptance criteria

| Do | Expect |
| --- | --- |
| `multipass list` on a format 2 store, then `multipass add x`, then `age -d` on the store | The store text starts `multipass 3`, every old entry has `modified 0`, and `x` has a current stamp |
| `multipass rm x`, then `age -d` on the store | `x` remains as a tombstone with `modified` and `deleted`, and `multipass list` does not show it |
| `multipass get x` after `rm x` | Fails with `no entry named x` |

Tests that must fail before the change and pass after it:

- **Merge laws**, over generated stores of a few entries with overlapping names, stamps, and tombstones: `merge([a, b])` equals `merge([b, a])`, `merge([merge([a, b]), c])` equals `merge([a, merge([b, c])])`, and `merge([a, a])` equals `a`. Catches a tie-break that depends on order, which would make two Macs write different stores.
- **Concurrent changes.** A store copied twice, with `x` added in one and `y` in the other, merges to hold both. Catches a merge that keeps one copy whole.
- **Edit against removal.** `x` edited in one copy and removed in the other keeps whichever has the later stamp, in both orders. Catches a tombstone that always wins or always loses.
- **Stamps after skew.** In a store whose newest stamp is an hour ahead of `now`, the next change is stamped one millisecond past it, and the warning does not fire; a day and a minute ahead, it fires. Catches a slow clock that loses to a change it already saw.
- **Old tombstones** are dropped by `to_text(cutoff)` a millisecond before the cutoff and kept at it, and a cutoff from an old key keeps a 200-day-old tombstone that 120 days alone would drop. Catches a store that grows forever, and one that forgets a removal while a file that predates it can still be merged.
- **Formats 1 and 2** read with `modified 0` on every entry, and format 3 round-trips through `to_text` and `from_text`, including a tombstone. A format 3 entry without `modified`, or a tombstone with a `secret`, fails with its line number. Catches an old store that stops opening, and a damaged store that parses.

## 5. Cost

Each entry grows by one short line. A merge of a few stores of a few hundred entries is a handful of map operations, too small to measure beside scrypt.

## 6. Open questions

None. The user chose immutable files merged per entry, newest change wins, and tombstones that expire.
