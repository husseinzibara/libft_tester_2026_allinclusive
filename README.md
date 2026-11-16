# libft tester (Ubuntu, Termux, iSH)

Self-contained: it needs no other tester. One command gives a projected score and two verdicts.

## How the moulinette grades (read off two real Deepthought traces)

1. **Gate.** Each `ft_*.c` is compiled alone with `-Wextra -Wall -Werror` and no `-I`, then
   `norminette` runs (only lines starting with `Error` / `Warning` count), then the Makefile is
   run: `make`, `make clean`, `make fclean`, rebuild. **Failing the gate gives a final grade of 0**
   and no function is tested (your first trace: one bad `#include <libft.h>` gave 0).
2. **Then every function is graded on its own.** Build 1 point, 13 functions x 2 points, 21 functions
   x 3 points, linked lists 10 points (9 functions) = 100. One broken function costs 2 or 3
   points, not the whole project.

The tester follows the same structure and prints a **projected moulinette score**. It is an
estimate: the moulinette's function tests are private, mine are a strict re-creation.

## Verdicts

| Verdict | Meaning |
|---|---|
| **FAIL (gate)** | a gate check failed, so the moulinette would stop with 0 |
| **OK** | gate passed and the projected score reaches the pass mark (80 by default, `--pass-mark N`) |
| **OUTSTANDING PROJECT STANDARDS** | full marks expected, no `[RISK]` item, every best-practice check passed |

If a best-practice check cannot run on your device (for example UBSan on a phone), the verdict is
marked **provisional** and the skipped check is named. Confirm it on Ubuntu.

## Tags

| Tag | Meaning |
|---|---|
| `[ OK ]` / `[FAIL]` | required: proven in a trace (gate, build) or a wrong result against libc / BSD semantics |
| `[RISK]` | not proven in a trace, but a known risk: subject rules (README, forbidden functions, `-Werror` in the Makefile, no relink, wildcard) and classic-tester edge cases (calloc zero / impossible sizes, malloc size classes) |
| `[OUTSTANDING]` / `[NOT YET]` | best practice. **None of these changes what a function returns**, so applying them cannot break a test |

Memory errors found by the checker (leak, overflow, double free) are shown as `[FAIL]` but count as
**risk exposure**, not certain point loss: the moulinette may not notice them, valgrind in peer
evaluation will. Wrong results and real crashes in a plain run against your `libft.a` cost points.

## Setup and run

    ./run.sh /path/to/libft          # or run it from inside your libft folder
    ./run.sh /path/to/libft --quick  # 10% fuzz size: use this on a phone

| Platform | Install once |
|---|---|
| Ubuntu / Debian | `sudo apt install build-essential python3` |
| Termux (Android) | `pkg install clang make python binutils` |
| iSH (iOS) | `apk add build-base python3` |

If `./run.sh` is not executable (zip files lose the flag), use `sh run.sh`.
**a-Shell (iOS) is not supported** (no native `make` / `ar` / executables).
Install `norminette` (`pip install norminette`) to verify the Norm gate; without it the Norm check is
a heuristic shown as `[WARN]`, never as a pass.

Flags: `--quick`, `--no-color`, `--keep`, `--pass-mark N`, `--extras` (also list which functions crash on
NULL arguments: libc crashes on NULL too, it is not graded, change it only if you want to),
`--no-sanitizers` (force the built-in memory checker).
Exit code 0 means OK. A plain-text copy is saved as `libft_report.txt`.
The temp folder is searched in `$LIBFT_TESTER_TMP`, `$TMPDIR`, `$PREFIX/tmp`, `/tmp`, `~`; if none is
writable the tester stops with a message instead of running broken checks.

## What it checks

1. **Gate:** files present; every file compiles alone (cc, and clang if both exist); norminette;
   `make` builds `libft.a`; all 43 functions (lists included) are in `libft.a`; `clean`, `fclean`, `re`.
2. **Behaviour (14 groups, each in its own process):** ctype, mem*, str*, atoi, itoa, calloc, substr/join/trim,
   split, mapi/iteri, put*_fd, lists, classic edge cases (strnstr, strncmp, strlcpy, strlcat with `SIZE_MAX`),
   plus the `[RISK]` groups calloc edge cases and allocation sizes.
3. **The real archive:** the same tests linked against the `libft.a` your own Makefile built, in a plain
   run with no sanitizer, like the moulinette.
4. **Best practice:** header dependency in the Makefile, exact prototypes (more-const variants such as
   `const char *` in `ft_putstr_fd` are accepted), README sections and AI-use note, `size_t` for
   `strlcpy` / `strlcat`, malloc failure injection (the Nth `malloc` fails, N = 1..40, in 10 functions:
   must return NULL, not crash, not leak), no undefined behaviour (UBSan).

### Memory checking on every platform
AddressSanitizer + LeakSanitizer + UBSan where available. Otherwise a built-in guard-page allocator:
every block ends at an inaccessible page (overreads and overflows crash at once), guard bytes are
checked on free, invalid and double frees are reported, leaks are counted, and new memory is filled
with `0xCD` so a missing `'\0'` or missing zeroing shows. On glibc the tester also names the `ft_`
function behind a crash, bad free, leak or overflow; elsewhere it blames the whole group.

## Why the best-practice list never contradicts the original functions
Run against a libft whose non-allocating functions were thin wrappers around real libc, every
required, risk and best-practice behaviour check passed. The only flags were the intended ones
(libc calls are forbidden by the subject, and UBSan objects to libc's own `memcpy(dst, NULL, 0)`).
NULL-argument hardening is therefore not part of any verdict.

## Limits
* It cannot reproduce the moulinette's private tests; the projected score is an estimate.
* Verified on Ubuntu x86-64 in three memory-checking modes, with planted-bug tests. The Termux and
  iSH paths are written for those platforms but could not be run on a phone.
* The Norm and README rules are applied as far as known, so check the current subject.

## Files
`run.sh` (launcher) · `run.py` (runner) · `harness.c` (test groups; run one with `./harness <group>`)
