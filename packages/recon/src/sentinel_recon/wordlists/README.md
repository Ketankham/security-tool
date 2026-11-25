# Wordlists for directory/file brute forcing

Loaded through `sentinel_recon.wordlists.load(name)`. The rules below are enforced by
`packages/recon/tests/test_wordlists.py`.

## sentinel-core (`sentinel-core.txt`)

Sentinel's own list, written for this project. Format: `category<TAB>path`, one per line, `#`
comment lines and blank lines ignored. Categories: `config`, `backup`, `vcs`, `admin`, `api`.

Entry rules: no leading `/`, ASCII only, no whitespace, `#`, `?`, `%`, `..` or `FUZZ`, at most 200
characters, every path listed once. Every path probed by
`sentinel_checks.passive.exposed_files.PROBES` is included. Entries ending in an archive/dump suffix
(`.zip .tar .tar.gz .tgz .gz .bz2 .7z .rar .sql .sql.gz .dump .db .sqlite`) are always category
`backup`; they are only ever checked with a guarded HEAD request, never fetched by ffuf.

The list is requested with plain GET against client sites, so it holds nothing that could change
state (no logout, delete, reset, install/setup, upload handlers, checkout, cron, password flows).
Every entry passes `sentinel_core.scope_guard.DestructiveActionGuard`.

## seclists-common (`seclists-common.txt`)

`Discovery/Web-Content/common.txt` from [SecLists](https://github.com/danielmiessler/SecLists)
(MIT licence, see `SECLISTS-LICENSE`), one path per line. Every entry gets category `common`.

| | |
|---|---|
| Source URL | https://raw.githubusercontent.com/danielmiessler/SecLists/2026.2/Discovery/Web-Content/common.txt |
| Pinned ref | release tag `2026.2` (see note below) |
| Fetched | 2026-11-25 |
| Original size / sha256 | 38536 bytes, `47fb86ca6fb3f97e5491161581900d6d99851fb16764eacddf16aa85617c956a` |
| Original lines | 4751 (no blank or comment lines) |
| Shipped entries | 4737 |
| Shipped size / sha256 | 38285 bytes, `8f259103273afdbafa0c656e09c4b79b37feaad3f10510be43d4dab408853101` |

The licence text (`SECLISTS-LICENSE`) is the `LICENSE` file at the same tag
(sha256 `3dbdc93d5f8829de0941744841730a09c106d0732e5ae0e98ca1d77be7ded66c`).

Note on the pin: the build sandbox could reach `raw.githubusercontent.com` only, not the GitHub
API or github.com, so the commit SHA behind the tag could not be looked up. The tag `2026.2` was
used as the ref instead and the original file's sha256 above is the real pin. At fetch time the
tag and `master` served identical bytes. To re-verify, download the source URL and compare the
sha256 with the one above.

The file is the original minus 14 lines, in the original order and otherwise unmodified:

* 3 contain whitespace: `Documents and Settings`, `Program Files`, `reports list`
* 3 contain `?`: `render?url=https://www.google.com`, and two `dns-query?...` entries
* 8 are flagged by `DestructiveActionGuard`: `delete`, `drop`, `logout`, `oauth/revoke`, `remove`,
  `signout`, `token/revoke`, `unsubscribe`
* 1 duplicate: `mcp` (the second occurrence)

The guard only knows a fixed set of destructive words. Names such as `install`, `setup`, `upload`,
`cron`, `register` and `forgot-password` remain in this list, so the worker
must keep applying the scope rules to every request, as it does for all wordlists.

## Read-only screen at load time

`load()` drops every entry that contains a state-changing word (log out,
delete, install, setup, upload, cron, register, forgot, checkout, ...; see
`STATE_CHANGING_WORDS` in `__init__.py`). The shipped `seclists-common.txt` is
kept as downloaded so its hash matches upstream; the screen removes the risky
names when it is loaded, and `Wordlist.skipped_state_changing` says how many.
Brute force requests every path with plain GET on live client sites, so a name
like `install` or `forgot-password` is never requested. The worker's scope
filter (path exclude rules) is applied on top of this.
