---
status: ready
priority: next
---

# Websites

Each entry can list the websites where its password is used, any number of them, and `multipass find <url>` names the entries for a page, so a browser extension or the Mac and iPhone app can offer the right entry on the right site.

## 1. Problem

An entry has a name and five kinds of field: `secret`, `username`, `notes`, `otp`, and, with the mergeable store, earlier secrets. The name is only a label you choose, such as `github.com work`, and nothing in multipass reads it as a website. So no program can ask multipass which entries belong to the page it is showing.

That blocks two things you want. A browser extension that offers the right login on each site needs a list of sites per entry. The passkeys plan's app hosts an AutoFill credential provider extension, and macOS and iOS offer a provider's passwords on a site only when the provider registers each password with the site's domain (`ASCredentialServiceIdentifier`). Many accounts also sign in at more than one place, such as `accounts.example.com` and `portal.example.com`, or a company's separate admin and user portals, so one entry needs several websites.

## 2. Solution

A new repeatable field, `website`, holds one web address per line, in any number. `multipass add <name> --website <url>` sets them when you add an entry, and `multipass website <name>` lists, adds, and removes them later without touching the secret. `multipass find <url>` prints the names of the entries whose websites match a page. A website matches a page when the page uses the same host or a subdomain of it, with the same port and the same scheme, except that a website saved as `http` also matches its `https` page. A leading `www.` is ignored when the two hosts are compared for equality, but never widens the subdomain test. The field needs a new store format number. Websites are not secrets, but they live inside the encrypted store like everything else, so the file on disk still reveals nothing about your accounts.

```console
$ multipass add "example work" --username sam --website accounts.example.com --website https://portal.example.com/login
$ multipass website "example work" --add admin.example.com
$ multipass website "example work"
https://accounts.example.com
https://portal.example.com/login
https://admin.example.com
$ multipass find https://portal.example.com/dashboard
example work
```

### 2.1 The field

```text
multipass 4
example work
	modified 1764260000000
	secret hunter2
	username sam
	website https://accounts.example.com
	website https://portal.example.com/login
	website https://admin.example.com
```

| Rule | Detail |
| --- | --- |
| Repeatable | An entry holds zero or more `website` lines, in the order you added them. A duplicate, after normalizing, is refused with `example work already lists https://admin.example.com`. |
| Normalized on input | A value without `://` is a bare host, so `github.com` becomes `https://github.com`. The scheme and host are lowercased. A port loses any leading zeros, and a default port (`:443` for `https`, `:80` for `http`) is dropped. A path that is only `/`, with no query or fragment, is dropped, so `github.com` and `https://github.com/` are one value. Any other path, query, or fragment is kept as you typed it, because it names the login page to open. |
| Allowed values | `https` and `http` addresses with an ASCII host, parsed as the list below says. Any other scheme, a host with characters outside ASCII, or a value with a space or control character is refused, naming the value. A host in another script must be entered in its `xn--` form, because converting it needs Unicode's IDNA tables, which would be a large data file. |
| Not a secret | The field is ordinary text, escaped like every field. A command's own errors may name the website you passed, but a malformed `website` line in the decrypted store fails with its line number only, as every store error does. |

A website is parsed strictly, so that `find` and a browser never disagree about which host a page is on. The value is a scheme, `://`, an authority, and an optional path, query, and fragment. The authority ends at the first `/`, `?`, or `#`, or at the end of the value. The host is the authority up to its first `:`, and the port is the rest of the authority after that `:`. multipass refuses, naming the value, each form that a browser reads in a way this split would not:

- **`http:` or `https:` followed by anything but `//`**, such as `https:bank.example` or `https:/bank.example`, which a browser repairs. Such a value is refused rather than read as a bare host.
- **An `@` in the authority.** A browser reads `https://bank.example@evil.example/` as a user name on the host `evil.example`. The error for this case does not repeat the value, because the text before the `@` may be a password: `a website cannot hold a user name or password`. multipass runs this check before every other rule, and no error names a refused value that holds an `@` anywhere, so `ftp://sam:hunter2@files.example` and `https:sam:hunter2@bank.example` are refused without printing the password.
- **A `\` anywhere in the value.** A browser reads it as `/`, so it loads `https://evil.example\@bank.example/` from `evil.example`.
- **A `%` in the authority.** A browser decodes percent-encoding in a host, so it reads `bank%2Eexample` as `bank.example`.
- **A host with any character but ASCII letters, digits, `-`, and `.`, or with an empty label**, such as `a..example` or a leading or trailing dot. This also refuses a bracketed IPv6 address.
- **A host whose last label is all digits or starts with `0x`**, unless the whole host is four decimal numbers from 0 to 255 without leading zeros. A browser reads `0x7f.1`, `2130706433`, and `010.0.0.1` as IPv4 addresses.
- **A port that is empty, has a character other than a digit, or is above 65535.**

### 2.2 Matching

`find <url>` and every later caller use one function, `website::matches(stored, page)`:

1. Both addresses are parsed and normalized as § 2.1 says. `find` refuses a page address that § 2.1 refuses, naming it, as `add` does.
2. The schemes must agree, except that a stored `http` address also matches an `https` page, since a site that moved to `https` is still that site. A stored `https` address never matches an `http` page, so a password is never offered over plain HTTP when you saved it for HTTPS.
3. The ports must agree, compared as § 2.1 leaves them. A default port is dropped, so a stored `http://example.com` and the page `https://example.com` both have no port, and step 2 decides. Comparing the ports a browser connects to, 80 and 443, would stop a stored `http` address from ever matching its `https` page.
4. The hosts match when they are equal once a leading `www.` is removed from each, provided what remains still has a dot, so `www.example.com` and `example.com` are one host. Otherwise the page's host must end with `.` followed by the stored host as written, `www.` included. So `example.com` matches `portal.example.com`, but `portal.example.com` does not match `example.com` or `admin.example.com`, `example.com` never matches `notexample.com`, and a stored `www.host.example` never matches `anyone.host.example`. An IPv4 address matches only itself.
5. The path is ignored.

`find` prints each matching entry's name once, sorted, and exits as `grep` does, so a script can tell the cases apart without reading stderr:

| Exit status | Meaning |
| --- | --- |
| 0 | At least one entry matches. |
| 1 | No entry matches. Related entries, if any, are named on stderr. |
| 2 | Any error, such as a usage error, a refused page address, a wrong passphrase, a store that cannot be read, or a Touch ID sheet you decline (`the request was not approved`). |

`main` turns every error into status 1 today, before a command can choose its own, so `find` returns its status the way `upgrade` does, and every error on its path exits 2. That path starts at `parse`, which returns a usage error to `main` before any command's own route runs, so a usage error from `upgrade`, such as `multipass upgrade 0.2`, exits 1. Copying `upgrade`'s route alone would leave `find`'s usage errors at 1 too, so `main` gives a usage error for `find` status 2. `parse` meets an unknown option, such as the `--bogus` in `multipass find --bogus https://github.com`, in its option loop, which can run before it has read the command word. So `parse` returns the command word with every usage error, as the first positional argument, scanning the rest of the arguments for it when the error comes first, and `main` gives status 2 when that word is `find`. The scan skips the value of each option that takes one, such as `--store`, `--username`, `--notes`, and `--field`, so in `multipass --bogus --store s find x` the command word is `find`, not `s`. `main` refuses an argument that is not valid UTF-8 before `parse` runs, and that error also exits 2 when the command word is `find`, found by the same scan over the arguments that are valid UTF-8. Every other command keeps the statuses it has today: 1 on any error, except `upgrade`, which passes the installer's status through and stops with 65 or 69 when its own checks fail, as the installer plan's § 2.3 describes. `find` opens the store the way `get` does.

Without a session, `find` asks for the passphrase, and on a Mac with Touch ID or a watch it starts the session agent, as the README's section on staying unlocked describes, whether or not anything matches. `run` starts the agent only once the command returns `Ok`, so `find` reports no match as a result rather than as an error, and a lookup that finds nothing still leaves the next one asking for a touch rather than the passphrase.

During a session, `find` sends the agent a new request, `Find(page)`, as `find <n>` followed by the `n` bytes of the page address, the way `read <n>` sends a name. The agent normalizes the address itself, as § 2.1 says, because any program running as you can send a `find` line. When § 2.1 refuses the address, the agent closes the connection without showing a sheet, as it does for a request it cannot read. Otherwise it shows one sheet that names the normalized address's host, such as "multipass is trying to find logins for admin.example.com". Once a touch approves it, the agent runs `website::matches` and `website::related` against its own store, and replies with the names of the matching entries and, for each related entry, its name and the website that relates it, so `find` can print the hint. The reply is `ok <n>` followed by `n` bytes of lines: `match <name>` for each matching entry, and `related <website> <name>` for each related one. Each name is escaped as `list`'s reply escapes it, and the website comes before the name because § 2.1 refuses a website with a space. The agent can also reply as it does to `read` and `list`, in the session-unlock plan's § 2.6 table, and `find` treats each reply as `get` does:

| Reply | What `find` does |
| --- | --- |
| `denied` | Exits 2 with `the request was not approved`. |
| `unavailable` | Asks for the passphrase, because neither Touch ID nor a watch could answer, and the session stays. |
| `stale` | Asks for the passphrase and says why, because the session ended. |
| `failed <n>` | Exits 2 with the `n` bytes of the agent's error. |

The reply never carries a secret, a username, notes, a one-time password key, or history, and websites are not secrets (§ 2.5).

This meets AGENTS.md's rule for the session agent: it answers a request only after Touch ID or a watch approves that one request, and it reads only what the sheet names. A `find` request is for a page, not one entry, so its sheet names the page's host where the rule says the entry, as `list`'s sheet says "list your entries", and its reply holds no more than names and websites.

When nothing matches, `find` looks for related entries: those with a website whose root domain is the page's root domain, under the same scheme rule. It prints none of them on stdout, so stdout still holds only real matches. It names each on stderr with the website that relates it and the command that would add the page's scheme, host, and port, then exits 1. The command leaves out the page's path, query, and fragment, because a login page's query can carry a one-time token, which belongs neither in the store nor on stderr:

```console
$ multipass find https://admin.example.com/login
multipass: no entry lists admin.example.com; related: example work (https://portal.example.com/login)
multipass: to use it here, run: multipass website "example work" --add https://admin.example.com
```

A related entry is a hint for you to confirm, never a match, so nothing fills it in or offers it as a login. That lets the root domain come from a short rule rather than the Public Suffix List, in `website::root(host)`:

1. Take the last two labels of the host, such as `example.com` for `portal.example.com`.
2. When the last label has two letters, a country code, and the label before it is one of `co`, `com`, `net`, `org`, `gov`, `edu`, `ac`, `ne`, or `or`, take the last three instead, such as `example.co.uk`.

An IPv4 address has no root domain, so it relates to no other host.

The rule is wrong for some hosts, such as two sites under `github.io`, which it calls related. A wrong hint costs you only a suggestion you ignore.

### 2.3 Commands

| Command | Effect |
| --- | --- |
| `add <name> --website <url>` | Repeatable. Sets the new entry's websites. With `--force` on an existing entry, the websites you pass replace the old ones, and with no `--website` the old ones stay, as `--force` keeps the one-time password today. |
| `website <name>` | Lists the entry's websites, one per line. |
| `website <name> --add <url>` | Repeatable in one command. Appends websites. |
| `website <name> --remove <url>` | Repeatable. Removes websites, matching the normalized value exactly, and fails naming any that is not listed. |
| `find <url>` | Prints the names of the matching entries, or, when none matches, names the related entries on stderr with the command that adds the page (§ 2.2). |
| `get <name> --field website` | Prints the websites, one per line, like `website <name>`. |

Changing websites is a change to the entry, so it takes a stamp from `Store::stamp` and merges like any other change. The mergeable store merges whole entries, not fields: for each name, the version with the newest `modified` wins, and the losing version's secret joins the winner's history. So two Macs that change the same entry's websites before seeing each other's change keep the newer list. And when one Mac changes an entry's secret and another, before it sees that change, changes the same entry's websites, the websites change wins the whole entry, and the newer secret survives only in the entry's history.

### 2.4 Store format

This plan builds on the mergeable store, which supplies format 3, the `modified` line, `Store::stamp`, and the earlier secrets § 1 counts, so it ships after that plan. Adding a field means a new `multipass <n>` header, and `Store::from_text` keeps reading every earlier format. The passkeys plan, a draft waiting on a prototype, has claimed format 4. This plan is smaller and likely ships first, so it takes format 4, and the change that builds it moves the passkeys plan to format 5. If passkeys ships first, this plan takes the next number instead. Either way, an entry in the new format may hold `website` lines, and a store from an older format reads with none.

### 2.5 Changes by file

| File | Change |
| --- | --- |
| `src/website.rs` | New. `normalize(&str) -> Result<String>`, `matches(stored, page) -> bool`, `root(host) -> &str`, and `related(stored, page) -> bool`, with no cryptography, since websites are not secrets. |
| `src/store.rs` | `Entry::websites: Vec<String>`, the `website` field line, and the new format number. |
| `src/agent.rs` | `Request::Find(page)`, sent as `find <n>` and the page address the way `read` sends a name. The agent normalizes the address and closes the connection without a sheet when § 2.1 refuses it, shows the sheet reason `find logins for <host>`, and replies `ok <n>` with `match` and `related` lines as § 2.2 describes. |
| `src/main.rs` | `--website` on `add`, the `website` and `find` commands, `--field website`, and `USAGE`. `find` exits 0, 1, or 2 as § 2.2 describes, rather than through `ExitCode::FAILURE`. |
| `README.md` | A section on websites and `find`, which gives `find`'s exit statuses, the section on staying unlocked adds `find` to the commands that ask for a touch and rewords its sentences that every sheet names the entry and that the agent hands over only the entry the sheet names, since a `find` sheet names a host and its reply names several entries, and the recovery example shows a `website` line. The opening advice to keep everyday logins in a full password manager stays, because nothing fills a login in a browser until the browser extension's plan ships, and that plan revisits it. |
| `AGENTS.md` | The session-agent rule says that a `find` sheet names the page's host rather than an entry, and that its reply carries only entry names and websites. The store format note names the new number and says in the note itself that format 4 adds the `website` field, and that format 5 adds the `passkey` field once passkeys ships. It points to the mergeable-store plan's § 2.1 table for formats 1 to 3 only, because that plan is `completed` and its table names format 4 as the passkey field, and a completed plan is left as it is. |
| `docs/projects/passkeys/readme.md` | Format 4 becomes format 5, and § 2 notes that the app can register each entry's websites with the system's credential identity store for password AutoFill. |

## 3. Why this design

- **A repeatable field, not a list in one line.** Each `website` line is one value, like every other field, so the store text stays readable with `age -d` and needs no separator that a web address could contain.
- **Match by host and subdomain, without the Public Suffix List.** Matching every host under the same registrable domain, as some password managers do, needs the Public Suffix List to know that `example.co.uk` is one site but `co.uk` is not. That list is a data file of a few hundred kilobytes that its maintainers update often, so multipass would have to ship and refresh it. Matching the stored host and its subdomains needs no list. It also never offers a password across tenants of a shared host, such as two sites under `github.io`, because an entry stores the tenant's own host.
- **Hints by root domain, matches by host.** The owner chose strict matching with a hint: few unrelated sites share a root domain, so a related entry is usually the right one, but only you can say so. Showing it as a hint with the command to add the page keeps matching exact, and each confirmed hint becomes an exact match from then on.
- **Strict parsing.** A parser that finds the host differently from a browser lets a page on one host match a website on another, so § 2.1 refuses every form that browsers repair or read in a surprising way, rather than copying the URL standard's repair rules. A refused address costs you only retyping it.
- **`www.` ignored for equality only.** Sites serve the same login with and without `www.`, so treating them as one host saves you a second line for nearly every site. Removing it before the subdomain test would widen a stored `www.host.example` to every subdomain of `host.example`. On a platform that serves its own login at `www.host.example` and each user's site at `<user>.host.example`, that would offer the platform's password on a page another user controls.
- **HTTPS never downgrades.** Offering a password saved for `https` to an `http` page would send it in the clear.
- **`find` in the CLI now.** A browser extension, and the app's AutoFill registration, both need "which entries belong to this page". Building it once in Rust, with tests, gives every later caller the same answer. Once the app registers each entry's websites with the system's credential identity store, the system's own matching picks the passwords AutoFill suggests, so `website::matches` decides there only where the app or the extension filters the list itself.
- **Deferred: the browser extension.** It needs a way for the browser to reach multipass, such as Chrome's native messaging host, and a decision about how it unlocks the store, which the session-unlock plan's agent may answer. Its own plan comes later.
- **Deferred: per-site password rules.** The password-generation plan's `--rules` could later look up a site's rules by an entry's website, from Apple's open `password-manager-resources` data. That needs this field first.

## 4. Acceptance criteria

| Do | Expect |
| --- | --- |
| `multipass add x --website github.com --website https://Gist.GitHub.com:443/` then `multipass website x` | `https://github.com` and `https://gist.github.com` |
| `multipass website x --add https://github.com/` | Fails: `x already lists https://github.com` |
| `multipass website x --add github.com` | Fails: `x already lists https://github.com` |
| `multipass find https://www.github.com/login` | Prints `x` and exits 0 |
| `multipass find http://github.com` | Exits 1 with no output, because the entry stored `https` |
| `multipass find https://notgithub.com` | Exits 1, with no related entry |
| During a session, with `x` listing `https://github.com`, `multipass find https://www.github.com/login`, then the same command with the sheet declined | The first shows one sheet reading `multipass is trying to find logins for www.github.com`, then prints `x` and exits 0. The second exits 2 with `the request was not approved`, and nothing on stdout. |
| `multipass --bogus --store s find x` | Exits 2 with a usage error, and nothing on stdout |
| `multipass find` with an argument that is not valid UTF-8 | Exits 2 with `arguments must be valid UTF-8` |
| `multipass find --bogus https://github.com` | Exits 2 with a usage error, and nothing on stdout |
| With no session, on a Mac with Touch ID, `multipass find https://notgithub.com` with the passphrase, then `multipass find https://github.com` | The first exits 1 and starts the agent. The second shows a Touch ID sheet rather than asking for the passphrase, then prints `x`. |
| `multipass find` with no address | Exits 2 with a usage error, and nothing on stdout |
| `multipass find https://github.com` with the wrong passphrase | Exits 2 with the wrong-passphrase error, and nothing on stdout |
| `multipass find https://github.com@evil.example/` | Exits 2 with `a website cannot hold a user name or password`, and names no entry |
| `multipass find 'https://evil.example\@github.com/'` | Exits 2 with `a website cannot hold a user name or password`, without naming the address, because the `@` check runs first, and names no entry |
| `multipass find 'https://evil.example\github.com/'` | Exits 2 naming the address, because it holds a backslash, and names no entry |
| `multipass find 'https://evil.example#@github.com'` | Exits 1 with nothing on stdout, because the host is `evil.example` |
| `multipass add z --website https://sam:hunter2@bank.example` | Fails with `a website cannot hold a user name or password`, and neither output contains `hunter2` |
| With `w` listing only `https://www.host.example`, `multipass find https://host.example` and then `multipass find https://anyone.host.example` | The first prints `w`. The second exits 1 with nothing on stdout and names `w` on stderr only as related. |
| With `y` listing only `https://portal.example.com`, `multipass find 'https://admin.example.com/login?token=abc'` | Exits 1 with nothing on stdout. Stderr names `y`, its website, and `multipass website y --add https://admin.example.com`, without the path or query. |
| `multipass website x --remove https://github.com`, then `age -d` on the store | The store shows only the `gist.github.com` line for `x`, and the entry's `modified` changed |
| `multipass add y --website ftp://example.com` | Fails, naming `ftp://example.com` |
| A store from the previous format | Opens, with no websites on any entry |

Tests that must fail before the change and pass after it:

- **Matching table.** Each row of § 2.2 as a pair that matches and one that does not, including `example.com` against `notexample.com`, `www.` on either side, a stored `www.host.example` against `host.example`, which matches, and against `anyone.host.example`, which does not, a stored `http` against an `https` page, the reverse, a different port, and an IPv4 address against a longer host that ends with it. Catches a suffix test without the dot, which would offer a password to a look-alike domain, and a `www.` removal that widens the subdomain test.
- **Look-alike addresses.** `https://bank.example@evil.example/`, `https://evil.example\@bank.example/`, `https://bank%2Eexample/`, `https:bank.example`, `https://bank.example:/`, `https://bank.example:99999/`, `https://[::1]/`, `https://0x7f.1/`, `https://010.0.0.1/`, `https://bank.example./`, and `https://a..example/` are each refused, and the errors for the first two do not contain `bank.example`. `ftp://sam:hunter2@files.example` and `https:sam:hunter2@bank.example` are refused with errors that do not contain `hunter2`. `https://evil.example#@bank.example` and `https://evil.example?@bank.example` parse with the host `evil.example`. Catches a parser that finds the host differently from a browser, which would offer a bank's password on another site.
- **Agent `find`.** With a test approver, a declined `find` request gets no reply but the refusal, and an approved one replies with the matching and related names and the website that relates each, but with no entry's secret, username, or notes. A `find` line whose address § 2.1 refuses closes the connection before the approver is asked. Catches a reply that hands over a secret without a sheet naming its entry.
- **Root domains.** `root` gives `example.com` for `a.b.example.com`, `example.co.uk` for `portal.example.co.uk`, and `example.com` for `example.com`, and `related` never holds where `matches` does. Catches a rule that calls `co.uk` a root domain, which would relate every British site to every other.
- **Normalizing.** Uppercase hosts, default ports, a port with leading zeros, a bare host, a lone `/` dropped and a trailing slash after a path kept, and each refused value. Catches two spellings of one site that would both be stored.
- **Round trip.** An entry with three websites goes through `to_text` and `from_text` unchanged and in order, and a merge of two versions keeps the newer version's list whole. A store with a malformed `website` line fails `from_text` with an error that names the line number and does not contain the line. Catches a merge that interleaves two lists, and a store error that prints a line of the decrypted store.

## 5. Cost

Each website adds one short line to its entry. `find` compares the page with every stored website, a few hundred string comparisons for a few hundred entries, against a third of a second of scrypt to open the store.

## 6. Open questions

1. **How strictly a website matches.** Decided by the owner: the same host or any subdomain of it, with `www.` ignored, and an entry that shares only the page's root domain is shown as a hint you can add, as § 2.2 describes. The rejected alternative was matching the whole site, every host under the same registrable domain, which needs the Public Suffix List as a data file.
2. **How `find` reports no match.** Decided by the owner: exit statuses as `grep` uses them, 0 for a match, 1 for no match, and 2 for an error, as § 2.2 describes, while every other command keeps the statuses it has today, 1 on any error except for `upgrade`, which passes the installer's status through. `find` is the one command a script tests for "no match", and it is new, so no script depends on its status. The rejected alternative was exit 1 for every failure, which leaves a script reading stderr to tell a missing entry from a wrong passphrase.
3. **How `find` opens the store during a session.** Decided by the owner: `find` sends the session agent a `Find(page)` request behind one Touch ID sheet that names the page's host, and the agent replies with only the names and websites of the matching and related entries, never a secret, as § 2.2 describes. The rejected alternative was for `find` to always ask for the passphrase, as `init`, `passwd`, and `rekey` do, which adds nothing to the agent but costs a passphrase prompt on every lookup.
