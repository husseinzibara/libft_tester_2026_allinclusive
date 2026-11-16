#!/usr/bin/env python3
"""libft tester - portable: Ubuntu/Linux, Android (Termux), iSH on iOS.

How the verdicts work (modelled on two real Deepthought traces):
  The moulinette first runs a GATE (each file compiled alone, then norminette, then the
  Makefile build). Failing the gate gives a final grade of 0 and no function is tested.
  After the gate every function is graded on its own (13 x 2 pts, 21 x 3 pts, lists 10 pts,
  build 1 pt = 100). So one broken function costs 2-3 points, not the whole project.

  OK                             no gate failure and the projected score reaches the pass mark
  OUTSTANDING PROJECT STANDARDS  full marks expected, no risk items, every best-practice check passed

Usage:  ./run.sh [path/to/libft] [--quick] [--no-color] [--keep] [--extras]
                 [--pass-mark N] [--no-sanitizers]
Your sources are copied to a temp folder; nothing in your project is modified.
"""
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

REQ_FILES = """ft_atoi ft_bzero ft_calloc ft_isalnum ft_isalpha ft_isascii ft_isdigit ft_isprint ft_itoa
ft_lstadd_back ft_lstadd_front ft_lstclear ft_lstdelone ft_lstiter ft_lstlast ft_lstmap ft_lstnew ft_lstsize
ft_memchr ft_memcmp ft_memcpy ft_memmove ft_memset ft_putchar_fd ft_putendl_fd ft_putnbr_fd ft_putstr_fd
ft_split ft_strchr ft_strdup ft_striteri ft_strjoin ft_strlcat ft_strlcpy ft_strlen ft_strmapi ft_strncmp
ft_strnstr ft_strrchr ft_strtrim ft_substr ft_tolower ft_toupper""".split()

# points per function, read off the grades in a real 100/100 trace (build 1 + these + lists 10 = 100)
POINTS2 = "isalpha isdigit isalnum isascii isprint strlen memset bzero memcpy memmove toupper tolower putchar_fd".split()
POINTS3 = ("strlcpy strlcat strchr strrchr strncmp memchr memcmp strnstr atoi calloc strdup substr strjoin strtrim "
           "split itoa strmapi striteri putstr_fd putendl_fd putnbr_fd").split()
LISTS = "lstnew lstadd_front lstsize lstlast lstadd_back lstdelone lstclear lstiter lstmap".split()
WEIGHT = dict([("ft_" + f, 2) for f in POINTS2] + [("ft_" + f, 3) for f in POINTS3])

PROTOS = """ft_isalpha|int|int
ft_isdigit|int|int
ft_isalnum|int|int
ft_isascii|int|int
ft_isprint|int|int
ft_toupper|int|int
ft_tolower|int|int
ft_atoi|int|const char *
ft_bzero|void|void *, size_t
ft_calloc|void *|size_t, size_t
ft_memchr|void *|const void *, int, size_t
ft_memcmp|int|const void *, const void *, size_t
ft_memcpy|void *|void *, const void *, size_t
ft_memmove|void *|void *, const void *, size_t
ft_memset|void *|void *, int, size_t
ft_strchr|char *|const char *, int
ft_strdup|char *|const char *
ft_strlcat|size_t|char *, const char *, size_t
ft_strlcpy|size_t|char *, const char *, size_t
ft_strlen|size_t|const char *
ft_strncmp|int|const char *, const char *, size_t
ft_strnstr|char *|const char *, const char *, size_t
ft_strrchr|char *|const char *, int
ft_substr|char *|char const *, unsigned int, size_t
ft_strjoin|char *|char const *, char const *
ft_strtrim|char *|char const *, char const *
ft_split|char **|char const *, char
ft_itoa|char *|int
ft_strmapi|char *|char const *, char (*)(unsigned int, char)
ft_striteri|void|char *, void (*)(unsigned int, char *)
ft_putchar_fd|void|char, int
ft_putstr_fd|void|char *, int
ft_putendl_fd|void|char *, int
ft_putnbr_fd|void|int, int
ft_lstnew|t_list *|void *
ft_lstadd_front|void|t_list **, t_list *
ft_lstsize|int|t_list *
ft_lstlast|t_list *|t_list *
ft_lstadd_back|void|t_list **, t_list *
ft_lstdelone|void|t_list *, void (*)(void *)
ft_lstclear|void|t_list **, void (*)(void *)
ft_lstiter|void|t_list *, void (*)(void *)
ft_lstmap|t_list *|t_list *, void *(*)(void *), void (*)(void *)""".splitlines()

# Variants that are equally valid (more const than the subject text). They are never flagged.
PROTO_ALT = {
    "ft_putstr_fd": ["void|const char *, int"],
    "ft_putendl_fd": ["void|const char *, int"],
    "ft_lstsize": ["int|const t_list *"],
    "ft_lstlast": ["t_list *|const t_list *"],
}


def fl(*names):
    return ["ft_" + n for n in names]


# behaviour groups: (group, tier, label, functions the group exercises)
GROUPS = [
    ("ctype", "REQ", "ft_is*/ft_toupper/ft_tolower match libc for every int (-300..300)",
     fl("isalpha", "isdigit", "isalnum", "isascii", "isprint", "toupper", "tolower")),
    ("mem", "REQ", "memset/bzero/memcpy/memmove/memchr/memcmp (fuzz vs libc, overlaps, NULL with n=0)",
     fl("memset", "bzero", "memcpy", "memmove", "memchr", "memcmp")),
    ("str", "REQ", "strlen/strchr/strrchr/strncmp/strlcpy/strlcat/strnstr/strdup (fuzz, bytes >127, size SIZE_MAX)",
     fl("strlen", "strchr", "strrchr", "strncmp", "strlcpy", "strlcat", "strnstr", "strdup")),
    ("atoi", "REQ", "ft_atoi (whitespace, signs, INT_MIN/INT_MAX, junk)", fl("atoi")),
    ("itoa", "REQ", "ft_itoa (INT_MIN, INT_MAX, random values)", fl("itoa")),
    ("calloc", "REQ", "ft_calloc (zeroed memory)", fl("calloc")),
    ("substr_join_trim", "REQ", "ft_substr / ft_strjoin / ft_strtrim (fuzz + edge cases)", fl("substr", "strjoin", "strtrim")),
    ("split", "REQ", "ft_split (fuzz, empty, all-delimiters, '\\0' delimiter, no read past the terminator)", fl("split")),
    ("mapi_iteri", "REQ", "ft_strmapi / ft_striteri", fl("strmapi", "striteri")),
    ("put_fd", "REQ", "ft_putchar_fd / putstr_fd / putendl_fd / putnbr_fd (INT_MIN)",
     fl("putchar_fd", "putstr_fd", "putendl_fd", "putnbr_fd")),
    ("lists", "REQ", "linked lists: new/add_front/add_back (chains)/size/last/delone/clear/iter/map", fl(*LISTS)),
    ("known_cases", "REQ", "classic edge cases for strnstr, strncmp, strlcpy, strlcat, strchr, memchr",
     fl("strnstr", "strncmp", "strlcpy", "strlcat", "strchr", "strrchr", "memchr")),
    ("calloc_edges", "RISK", "ft_calloc edge cases (zero sizes give a pointer, overflow/impossible sizes give NULL)", fl("calloc")),
    ("alloc_sizes", "RISK", "allocations are the right size (same size class as needed, like the classic tester's MOK)",
     fl("calloc", "strdup", "itoa", "strjoin", "strmapi", "substr", "strtrim", "lstnew", "split")),
]
FAIL_FUNCS = "strdup substr strjoin strtrim itoa strmapi calloc lstnew split lstmap".split()

# ---------------------------------------------------------------- output
C = {}


def setup_colors(enabled):
    names = dict(RED="31", GRN="32", YLW="33", CYN="36", BLD="1", DIM="2")
    for k, v in names.items():
        C[k] = ("\033[%sm" % v) if enabled else ""
    C["RST"] = "\033[0m" if enabled else ""


LOG = []
RESULTS = []  # dicts: tier, name, status, info, gate


def say(msg=""):
    print(msg)
    sys.stdout.flush()
    LOG.append(re.sub(r"\033\[[0-9;]*m", "", msg))


def section(title):
    say("")
    say("%s== %s ==%s" % (C["BLD"], title, C["RST"]))


def add(tier, name, status, info="", gate=False):
    RESULTS.append(dict(tier=tier, name=name, status=status, info=info, gate=gate))
    tags = {
        ("REQ", "OK"): C["GRN"] + "[ OK ]",
        ("REQ", "FAIL"): C["RED"] + "[FAIL]",
        ("RISK", "OK"): C["GRN"] + "[ OK ]",
        ("RISK", "FAIL"): C["YLW"] + "[RISK]",
        ("BEST", "OK"): C["CYN"] + "[OUTSTANDING]",
        ("BEST", "FAIL"): C["YLW"] + "[NOT YET]",
        ("EXTRA", "OK"): C["DIM"] + "[extra: ok]",
        ("EXTRA", "FAIL"): C["DIM"] + "[extra: note]",
    }
    if status == "WARN":
        tag = C["YLW"] + "[WARN]"
    elif status == "SKIP":
        tag = C["DIM"] + "[SKIP]"
    elif status == "INFO":
        tag = C["DIM"] + "[info]"
    else:
        tag = tags.get((tier, status), "[?]")
    say(" %s%s %s%s" % (tag, C["RST"], name, (C["DIM"] + "  (gate)" + C["RST"]) if gate and status == "FAIL" else ""))
    for line in info.splitlines():
        if line.strip():
            say("          " + line)


# ---------------------------------------------------------------- process helpers
class Res(object):
    def __init__(self, rc, out, err, timed_out=False):
        self.rc, self.out, self.err, self.timed_out = rc, out, err, timed_out


def run(cmd, cwd=None, env=None, timeout=300):
    try:
        p = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as e:
        return Res(127, "", "cannot run %s: %s" % (cmd[0], e))
    try:
        o, e = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        o, e = p.communicate()
        return Res(124, o.decode("utf-8", "replace"), e.decode("utf-8", "replace"), True)
    return Res(p.returncode, o.decode("utf-8", "replace"), e.decode("utf-8", "replace"))


def first_line_with(text, pattern, width=110):
    for line in text.splitlines():
        if re.search(pattern, line):
            return line.strip()[:width]
    return ""


def make_workdir():
    cands = []
    for k in ("LIBFT_TESTER_TMP", "TMPDIR"):
        if os.environ.get(k):
            cands.append(os.environ[k])
    if os.environ.get("PREFIX"):
        cands.append(os.path.join(os.environ["PREFIX"], "tmp"))  # Termux
    cands += ["/tmp", "/var/tmp", "/usr/tmp", os.path.expanduser("~/.cache"), os.path.expanduser("~"), os.getcwd()]
    for base in cands:
        try:
            os.makedirs(base, exist_ok=True)
            return tempfile.mkdtemp(prefix="libft_tester.", dir=base)
        except Exception:
            continue
    print("error: could not create a temporary folder anywhere. Set LIBFT_TESTER_TMP to a writable folder.")
    sys.exit(2)


def which_any(*names):
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def platform_hint():
    if "com.termux" in os.environ.get("PREFIX", "") or os.path.isdir("/data/data/com.termux"):
        return "termux"
    try:
        if os.path.exists("/proc/ish") or "ish" in os.uname().release.lower():
            return "ish"
    except Exception:
        pass
    return "linux"


def arg_value(argv, flag, default):
    if flag in argv:
        i = argv.index(flag)
        if i + 1 < len(argv):
            return argv[i + 1]
    return default


# ---------------------------------------------------------------- main
def main(argv):
    quick = "--quick" in argv
    keep = "--keep" in argv
    nosan = "--no-sanitizers" in argv
    nowrap = "--no-wrap" in argv
    extras = "--extras" in argv
    pass_mark = int(arg_value(argv, "--pass-mark", "80"))
    color = sys.stdout.isatty() and "--no-color" not in argv and not os.environ.get("NO_COLOR")
    if "-h" in argv or "--help" in argv:
        print(__doc__)
        return 0
    skip_next = False
    pos = []
    for a in argv:
        if skip_next:
            skip_next = False
            continue
        if a == "--pass-mark":
            skip_next = True
            continue
        if not a.startswith("--"):
            pos.append(a)
    setup_colors(color)

    libft = pos[0] if pos else None
    if not libft:
        for cand in (".", os.path.join(HERE, "..")):
            if os.path.isfile(os.path.join(cand, "Makefile")) and os.path.isfile(os.path.join(cand, "libft.h")):
                libft = cand
                break
    if not libft or not os.path.isdir(libft):
        print("Run from your libft folder, or pass its path:  ./run.sh path/to/libft")
        return 2
    libft = os.path.abspath(libft)
    if not (os.path.isfile(os.path.join(libft, "Makefile")) and os.path.isfile(os.path.join(libft, "libft.h"))):
        print("%s has no Makefile / libft.h" % libft)
        return 2

    cc = os.environ.get("CC") or which_any("cc", "gcc", "clang")
    if not cc:
        print("No C compiler found.\n  Ubuntu: sudo apt install build-essential\n  Termux: pkg install clang make python binutils\n  iSH:    apk add build-base python3")
        return 2
    cc_ver = (run([cc, "--version"]).out.splitlines() or ["?"])[0]
    cc_is_clang = "clang" in cc_ver.lower()
    make = which_any("make", "gmake")
    ar = which_any("ar", "llvm-ar")
    nm = which_any("nm", "llvm-nm")
    clang = which_any("clang")

    work = make_workdir()
    src = os.path.join(work, "src")
    os.makedirs(src)
    for fn in os.listdir(libft):
        if fn.endswith((".c", ".h")) or fn in ("Makefile", "README.md"):
            p = os.path.join(libft, fn)
            if os.path.isfile(p):
                shutil.copy2(p, os.path.join(src, fn))

    plat = platform_hint()
    say("%slibft tester%s  -  project: %s" % (C["BLD"], C["RST"], libft))
    say("%s%s | python %s | platform: %s | pass mark: %d%s" % (C["DIM"], cc_ver, sys.version.split()[0], plat, pass_mark, C["RST"]))
    if plat in ("ish", "termux") and not quick:
        say("%s tip: on a phone, add --quick to shrink the fuzz runs (about 10x faster).%s" % (C["DIM"], C["RST"]))
    say("%s Tags: [FAIL] costs points or breaks the build  [RISK] not proven in a trace but a known risk%s" % (C["DIM"], C["RST"]))
    say("%s       [OUTSTANDING] best practice that never changes how a function behaves%s" % (C["DIM"], C["RST"]))

    # ============================================================ 1. files
    section("1. Gate: files")
    missing = [f + ".c" for f in REQ_FILES if not os.path.isfile(os.path.join(src, f + ".c"))]
    add("REQ", "all 43 required ft_*.c files present", "FAIL" if missing else "OK", "missing: " + " ".join(missing) if missing else "", gate=True)
    ok = os.path.isfile(os.path.join(src, "Makefile")) and os.path.isfile(os.path.join(src, "libft.h"))
    add("REQ", "Makefile and libft.h present", "OK" if ok else "FAIL", gate=True)

    # ============================================================ 2. moulinette compile
    section("2. Gate: each file compiled alone, no -I (the moulinette's 'initial_errors' stage)")

    def compile_stage(comp, label):
        d = os.path.join(work, "moul_" + label)
        os.makedirs(d, exist_ok=True)
        for fn in os.listdir(src):
            if fn.endswith((".c", ".h")):
                shutil.copy2(os.path.join(src, fn), d)
        fails = []
        for f in REQ_FILES:
            if not os.path.isfile(os.path.join(d, f + ".c")):
                continue
            r = run([comp, "-Wextra", "-Wall", "-Werror", "-Wall", "-Wextra", "-Werror", "-c", f + ".c", "-o", "compil_single_output"], cwd=d)
            if r.rc != 0:
                fails.append("%s.c: %s" % (f, first_line_with(r.err, "error") or r.err.strip()[:100]))
        name = "every file compiles alone with %s -Wall -Wextra -Werror" % label
        if fails:
            add("REQ", name, "FAIL", "%d file(s) fail:\n%s\nThe moulinette gives a final grade of 0 here, before testing any function." % (len(fails), "\n".join(fails)), gate=True)
        else:
            add("REQ", name, "OK")

    compile_stage(cc, os.path.basename(cc))
    if clang and not cc_is_clang:
        compile_stage(clang, "clang")

    # ============================================================ 3. norm (gate)
    section("3. Gate: Norm (the moulinette counts only lines starting with Error or Warning)")
    nbin = shutil.which("norminette")
    if nbin:
        files = [f + ".c" for f in REQ_FILES if os.path.isfile(os.path.join(src, f + ".c"))] + ["libft.h"]
        r = run([nbin] + files, cwd=src)
        errs = [l for l in (r.out + r.err).splitlines() if re.match(r"^(Error|Warning)", l)]
        add("REQ", "norminette (ft_*.c and libft.h)", "FAIL" if errs else "OK", "\n".join(e[:110] for e in errs[:8]), gate=True)
    else:
        issues = []
        for f in sorted(os.listdir(src)):
            if not (f.startswith("ft_") and f.endswith(".c")) and f != "libft.h":
                continue
            lines_ = open(os.path.join(src, f), errors="replace").read().split("\n")
            if not lines_[0].startswith("/* ****"):
                issues.append("%s: missing 42 header" % f)
            infn, n, nf = False, 0, 0
            for i, ln in enumerate(lines_, 1):
                if len(ln.expandtabs(4)) > 80:
                    issues.append("%s:%d: line over 80 columns" % (f, i))
                code = re.sub(r'"(\\.|[^"\\])*"', '""', ln)
                code = re.sub(r"/\*.*?\*/", "", code).strip()
                if ln == "{":
                    infn, n = True, 0
                    continue
                if ln == "}":
                    if infn and n > 25:
                        issues.append("%s: function body longer than 25 lines" % f)
                    infn = False
                    nf += 1
                    continue
                if infn:
                    n += 1
                if re.match(r"^(for|switch|do|goto)\b", code) or re.search(r"[;{}\s](for|switch|goto)\s*\(", " " + code):
                    issues.append("%s:%d: forbidden keyword" % (f, i))
                if "?" in code and ":" in code and not code.startswith("*"):
                    issues.append("%s:%d: ternary operator" % (f, i))
                if infn and re.match(r"^(int|char|size_t|unsigned|long|t_list|void)\b[^;(]*=[^=]", code):
                    issues.append("%s:%d: declaration with assignment" % (f, i))
            if nf > 5:
                issues.append("%s: more than 5 functions" % f)
        if issues:
            add("REQ", "Norm (heuristic only)", "WARN", "norminette is not installed, so the gate is NOT verified. Heuristic found:\n" + "\n".join(issues[:8]))
        else:
            add("REQ", "Norm (heuristic only)", "WARN", "norminette is not installed, so this gate is NOT verified (pip install norminette). The heuristic found nothing.")

    # ============================================================ 4. Makefile
    section("4. Gate: Makefile and libft.a (build, clean, fclean, rebuild)")
    mk = os.path.join(work, "mk")
    shutil.copytree(src, mk)
    archive = os.path.join(mk, "libft.a")
    if not make:
        add("REQ", "Makefile checks", "SKIP", "'make' is not installed (Termux: pkg install make, iSH: apk add make)")
    else:
        comp_re = re.compile(r"^(cc|clang|gcc|[\w./-]*cc|[\w./-]*clang)\s")
        r1 = run([make], cwd=mk)
        built = os.path.isfile(archive)
        add("REQ", "'make' builds libft.a", "OK" if (r1.rc == 0 and built) else "FAIL",
            "" if (r1.rc == 0 and built) else (r1.err.strip().splitlines() or r1.out.strip().splitlines() or ["make failed"])[-1][:110], gate=True)
        clines = [l for l in r1.out.splitlines() if comp_re.match(l) and " -c " in l]
        flags_ok = bool(clines) and all(("-Wall" in l and "-Wextra" in l and "-Werror" in l) for l in clines)
        add("RISK", "Makefile compiles with -Wall -Wextra -Werror (subject rule)", "OK" if flags_ok else "FAIL", "" if flags_ok else "some compile lines lack the three flags")
        if ar and built:
            names = set(l.strip() for l in run([ar, "t", archive]).out.splitlines())
            absent = [f + ".o" for f in REQ_FILES if f + ".o" not in names]
            add("REQ", "default 'make' puts all 43 functions (lists included) into libft.a", "FAIL" if absent else "OK",
                ("missing from libft.a: " + " ".join(absent)) if absent else "", gate=True)
        r2 = run([make], cwd=mk)
        relink = any(comp_re.match(l) or l.startswith("ar ") for l in r2.out.splitlines())
        add("RISK", "no relink: 2nd 'make' does nothing", "FAIL" if relink else "OK", "second make rebuilt something" if relink else "")
        rc = run([make, "clean"], cwd=mk)
        objs = [f for f in os.listdir(mk) if f.endswith(".o")]
        okc = rc.rc == 0 and not objs and os.path.isfile(archive)
        add("REQ", "'make clean' removes objects, keeps libft.a", "OK" if okc else "FAIL", gate=True)
        rf_ = run([make, "fclean"], cwd=mk)
        objs = [f for f in os.listdir(mk) if f.endswith(".o")]
        okf = rf_.rc == 0 and not objs and not os.path.isfile(archive)
        add("REQ", "'make fclean' removes objects and libft.a", "OK" if okf else "FAIL", gate=True)
        rr = run([make, "re"], cwd=mk)
        if not os.path.isfile(archive):
            run([make], cwd=mk)
        add("REQ", "'make re' rebuilds libft.a", "OK" if (rr.rc == 0 and os.path.isfile(archive)) else "FAIL", gate=True)
        mtxt = open(os.path.join(mk, "Makefile"), errors="replace").read()
        add("RISK", "'all' rule present", "OK" if re.search(r"^all\s*:", mtxt, re.M) else "FAIL")
        add("RISK", "Makefile does not use wildcard", "FAIL" if "wildcard" in mtxt else "OK", "wildcard found in Makefile" if "wildcard" in mtxt else "")
        if os.path.isfile(archive):
            os.utime(os.path.join(mk, "libft.h"), None)
            r3 = run([make], cwd=mk)
            rebuilt = any(comp_re.match(l) for l in r3.out.splitlines())
            add("BEST", "objects rebuild when libft.h changes (header dependency)", "OK" if rebuilt else "FAIL",
                "" if rebuilt else "touching libft.h did not trigger a rebuild")

    # ============================================================ 5. external symbols, header
    section("5. Subject rules: forbidden functions, header, prototypes")
    plain = os.path.join(work, "plain")
    os.makedirs(plain)
    objs = []
    for f in REQ_FILES:
        sfile = os.path.join(src, f + ".c")
        if os.path.isfile(sfile):
            o = os.path.join(plain, f + ".o")
            if run([cc, "-c", "-I", src, sfile, "-o", o]).rc == 0:
                objs.append(o)
    if not nm or not objs:
        add("RISK", "only malloc, free and write are called (subject rule)", "SKIP", "needs 'nm' (Termux: pkg install binutils, iSH: apk add binutils)")
    else:
        bad = set()
        for o in objs:
            for line in run([nm, "-u", o]).out.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[-2] == "U":
                    n = parts[-1]
                    if n in ("malloc", "free", "write") or re.match(r"^ft_[a-z_]+$", n) or n.startswith("__stack_chk") or n == "_GLOBAL_OFFSET_TABLE_":
                        continue
                    bad.add(n)
        add("RISK", "only malloc, free and write are called (subject rule)", "FAIL" if bad else "OK", ("uses: " + " ".join(sorted(bad))) if bad else "")

    pdir = os.path.join(work, "proto")
    os.makedirs(pdir)

    def try_compile(text, name):
        p = os.path.join(pdir, name + ".c")
        with open(p, "w") as fh:
            fh.write(text)
        return run([cc, "-Wall", "-Wextra", "-Werror", "-I", src, "-c", p, "-o", p + ".o"])

    r = try_compile('#include "libft.h"\n#include "libft.h"\nsize_t x;\nt_list *y;\nint main(void) { return (int)(x == 0 && y == 0) - 1; }\n', "hdr")
    add("RISK", "libft.h compiles standalone, has include guard", "OK" if r.rc == 0 else "FAIL", "" if r.rc == 0 else first_line_with(r.err, "error|warning"))
    consts = ('#include <stddef.h>\n#include <stdlib.h>\n#include "libft.h"\n'
              'static char mapf(unsigned int i, char c) { (void)i; return c; }\n'
              'int main(void)\n{\n    const char *cs = "abc"; const void *cv = "abc"; char buf[8]; size_t n = 3;\n'
              '    (void)ft_atoi(cs); (void)ft_memcpy(buf, cv, n); (void)ft_memchr(cv, \'a\', n); (void)ft_memcmp(cv, cv, n);\n'
              '    (void)ft_memmove(buf, cv, n); (void)ft_strchr(cs, \'a\'); (void)ft_strdup(cs); (void)ft_strlcat(buf, cs, n);\n'
              '    (void)ft_strlcpy(buf, cs, n); (void)ft_strlen(cs); (void)ft_strncmp(cs, cs, n); (void)ft_strnstr(cs, cs, n);\n'
              '    (void)ft_strrchr(cs, \'a\'); (void)ft_substr(cs, 0, n); (void)ft_strjoin(cs, cs); (void)ft_split(cs, \'a\');\n'
              '    (void)ft_strtrim(cs, cs); (void)ft_strmapi(cs, mapf);\n    return 0;\n}\n')
    r = try_compile(consts, "consts")
    add("RISK", "const-correct: functions accept const arguments, as libc does (breaks C++ testers if not)", "OK" if r.rc == 0 else "FAIL",
        "" if r.rc == 0 else "\n".join(l.strip()[:120] for l in r.err.splitlines() if re.search(r"warning|error", l))[:400])
    lines = ['#include <stddef.h>', '#include "libft.h"']
    for i, ln in enumerate(PROTOS):
        fn, ret, params = ln.split("|")
        lines.append("static %s (*chk%d)(%s) = %s;" % (ret, i, params, fn))
    lines += ["int main(void)", "{"] + ["    (void)chk%d;" % i for i in range(len(PROTOS))] + ["    return 0;", "}"]
    r = try_compile("\n".join(lines) + "\n", "protos")
    bad = []
    if r.rc != 0:
        for m in re.finditer(r"protos\.c:(\d+):", r.err):
            idx = int(m.group(1)) - 3
            if 0 <= idx < len(PROTOS):
                nm_ = PROTOS[idx].split("|")[0]
                if nm_ not in bad:
                    bad.append(nm_)
        if not bad:
            bad = ["(see compiler output)"]
        still = []
        for fn_ in bad:
            okalt = False
            for alt in PROTO_ALT.get(fn_, []):
                ret, params = alt.split("|")
                t = '#include <stddef.h>\n#include "libft.h"\nstatic %s (*chk)(%s) = %s;\nint main(void) { (void)chk; return 0; }\n' % (ret, params, fn_)
                if try_compile(t, "alt").rc == 0:
                    okalt = True
                    break
            if not okalt:
                still.append(fn_)
        bad = still
    add("BEST", "all 42 prototypes match libc / the subject (size_t, const); more-const variants are accepted", "FAIL" if bad else "OK",
        ("differ from the standard signature: " + " ".join(bad)) if bad else "")

    # ============================================================ 6. README
    section("6. Subject rules: README")
    rd = os.path.join(src, "README.md")
    if not os.path.isfile(rd):
        add("RISK", "README.md exists", "FAIL")
    else:
        txt = open(rd, errors="replace").read()
        add("RISK", "README.md exists", "OK")
        first = txt.split("\n")[0]
        ok = re.match(r"^\*This project has been created as part of the 42 curriculum by .+\.\*$", first) is not None
        add("RISK", "README first line is the required italic sentence", "OK" if ok else "FAIL",
            "" if ok else "expected: *This project has been created as part of the 42 curriculum by <login>.*")
        miss = [s for s in ("Description", "Instructions", "Resources") if not re.search(r"^#*\s*" + s, txt, re.I | re.M)]
        add("BEST", "README has Description, Instructions and Resources sections", "FAIL" if miss else "OK", ("missing: " + " ".join(miss)) if miss else "")
        used = re.search(r"\b(AI|Claude|ChatGPT|Gemini|Copilot)\b", txt) is not None
        add("BEST", "README says how AI was used (if it was)", "OK" if used else "FAIL",
            "" if used else "no mention of AI use found; ignore this item only if you used none")

    # ============================================================ 7. behaviour
    section("7. Behaviour: each function graded on its own, like the moulinette")
    san_dir = os.path.join(work, "san")
    os.makedirs(san_dir)
    probe_c = os.path.join(san_dir, "probe.c")
    with open(probe_c, "w") as fh:
        fh.write("#include <stdlib.h>\n#include <string.h>\nint main(void){char *p=malloc(8);if(!p)return 1;memset(p,0,8);free(p);return 0;}\n")
    wrap_c = os.path.join(san_dir, "wrapprobe.c")
    with open(wrap_c, "w") as fh:
        fh.write("#include <stdlib.h>\nvoid *__real_malloc(size_t); void __real_free(void*);\n"
                 "void *__wrap_malloc(size_t n){return __real_malloc(n);} void __wrap_free(void*p){__real_free(p);}\n"
                 "int main(void){char *p=malloc(8);if(!p)return 1;free(p);return 0;}\n")

    def probe(flags, env_extra=None):
        out = os.path.join(san_dir, "probe.bin")
        if os.path.exists(out):
            os.remove(out)
        if run([cc, probe_c] + flags + ["-o", out]).rc != 0:
            return False
        env = dict(os.environ)
        env.update(env_extra or {})
        return run([out], env=env, timeout=60).rc == 0

    asan = lsan = ubsan = False
    san_flags = []
    if not nosan:
        for combo in ("address,undefined", "address"):
            fl_ = ["-fsanitize=" + combo]
            if probe(fl_, {"ASAN_OPTIONS": "detect_leaks=1"}):
                asan, lsan, ubsan, san_flags = True, True, "undefined" in combo, fl_
                break
            if probe(fl_, {"ASAN_OPTIONS": "detect_leaks=0"}):
                asan, lsan, ubsan, san_flags = True, False, "undefined" in combo, fl_
                break
        if not asan and probe(["-fsanitize=undefined"]):
            ubsan, san_flags = True, ["-fsanitize=undefined"]
    wrap_ok = False
    if not nowrap:
        wrap_ok = run([cc, wrap_c, "-Wl,--wrap=malloc", "-Wl,--wrap=free", "-o", os.path.join(san_dir, "wrap.bin")]).rc == 0 and \
            run([os.path.join(san_dir, "wrap.bin")]).rc == 0

    if asan:
        mode_msg = "AddressSanitizer%s%s" % (" + LeakSanitizer" if lsan else "", " + UBSan" if ubsan else "")
    else:
        mode_msg = "built-in guard-page allocator (no AddressSanitizer on this platform): catches buffer over/underflow, " \
                   "invalid and double frees, missing terminators (new memory is filled with 0xCD) and leaks" + (" + UBSan" if ubsan else "")
    if not wrap_ok:
        mode_msg += "; linker cannot wrap malloc, so allocation-size and malloc-failure tests are skipped"
    add("REQ", "memory checker in use: " + mode_msg, "INFO")

    base_flags = ["-g", "-O1", "-fno-omit-frame-pointer", "-Wno-unused-result", "-w"] + san_flags
    objs = []
    build_fail = []
    for f in REQ_FILES:
        sfile = os.path.join(src, f + ".c")
        if not os.path.isfile(sfile):
            continue
        o = os.path.join(san_dir, f + ".o")
        r = run([cc] + base_flags + ["-I", src, "-c", sfile, "-o", o])
        if r.rc != 0:
            build_fail.append(f)
        else:
            objs.append(o)
    harness_bin = os.path.join(san_dir, "harness")
    hflags = list(base_flags)
    if not asan:
        hflags.append("-DGUARD_ALLOC")
    if wrap_ok:
        hflags += ["-Wl,--wrap=malloc", "-Wl,--wrap=free"]
    else:
        hflags.append("-DNO_WRAP")
    def link_harness(flags, inputs, out):
        """-rdynamic -ldl lets the harness name the ft_ function behind a crash (glibc); fall back without."""
        res_ = run([cc] + flags + [os.path.join(HERE, "harness.c")] + inputs + ["-rdynamic", "-ldl", "-o", out])
        if res_.rc != 0:
            res_ = run([cc] + flags + [os.path.join(HERE, "harness.c")] + inputs + ["-o", out])
        return res_

    hres = Res(1, "", "")
    if not build_fail and len(objs) == len(REQ_FILES):
        hres = link_harness(hflags, objs, harness_bin)

    san_names = {}
    lost_req = set()      # functions whose moulinette test would fail
    lost_risk = set()     # functions only at risk (edge cases not proven in a trace)
    behaviour_ran = False

    def make_env(fuzz, leaks):
        env = dict(os.environ)
        env["ASAN_OPTIONS"] = "detect_leaks=%d:allocator_may_return_null=1:abort_on_error=0" % (1 if leaks else 0)
        env["UBSAN_OPTIONS"] = "print_stacktrace=0"
        env["LIBFT_TESTER_TMP"] = work
        env["LIBFT_FUZZ"] = str(fuzz)
        return env

    class GR(object):
        def __init__(self):
            self.status, self.info = "OK", ""
            self.func, self.func_unknown = set(), False     # wrong results (certain loss)
            self.mem, self.mem_unknown = set(), False       # memory errors found by the checker
            self.crashed = False                            # no result: crash, abort or timeout
            self.crash_names = set()                        # ft_ functions on the stack at the crash (glibc)
            self.timed_out = False
            self.skip = ""

    def frames_funcs(err):
        out = set()
        for l in err.splitlines():
            if re.match(r"^\s*#[0-3]\s", l):
                mm = re.search(r" in (ft_\w+)", l)
                if mm:
                    out.add(mm.group(1))
        return out

    def eval_group(binary, env, g, group_funcs, ub_lines=None):
        r = run([binary, g], env=env, timeout=600)
        res = GR()
        info = []
        m = re.search(r"^@@RESULT (\d+) (\d+)", r.out, re.M)
        sk = re.search(r"^@@SKIP (.*)$", r.out, re.M)
        if sk:
            res.status, res.skip = "SKIP", sk.group(1)
            return res
        if r.timed_out:
            res.status, res.crashed, res.timed_out = "FAIL", True, True
            res.info = "timed out (infinite loop?)"
            return res
        if not m:
            res.status, res.crashed = "FAIL", True
            sig = ""
            if r.rc is not None and r.rc < 0:
                try:
                    sig = signal.Signals(-r.rc).name
                except Exception:
                    sig = "signal %d" % -r.rc
            a = first_line_with(r.err, r"ERROR: AddressSanitizer") or first_line_with(r.err, r"SEGV|runtime error")
            what = re.sub(r"^\S*/(ft_\w+\.c)", r"\1", re.sub(r"^==\d+==\s*", "", a))[:100] or ("killed by " + sig if sig else "no result (exit code %s)" % r.rc)
            info.append("crashed: " + what)
            fns = frames_funcs(r.err)
            res.crash_names = set(re.findall(r"^@@CRASHFN (ft_\w+)", r.out, re.M))
            fns = fns | res.crash_names
            if fns:
                res.mem |= (fns & set(group_funcs)) or fns
                info.append("in " + ", ".join(sorted(fns)))
            else:
                res.mem_unknown = True
                if sig in ("SIGSEGV", "SIGBUS"):
                    info.append("read/write outside a buffer, or a NULL dereference (run on a PC with ASan for the exact line)")
        else:
            nf = int(m.group(2))
            if nf:
                res.status = "FAIL"
                flines = [l for l in r.out.splitlines() if l.startswith(("FAIL", "NULL-unsafe"))]
                for l in flines:
                    sm = re.search(r"subject=(ft_[a-z_]+)", l)
                    ff = {sm.group(1)} if sm else set(re.findall(r"ft_[a-z_]+", l))
                    if ff:
                        res.func |= ff
                if not res.func:
                    res.func_unknown = True
                info.append("%d wrong result(s): %s" % (nf, "; ".join(flines[:3])[:220]))
            mem = re.search(r"^@@MEM live=(-?\d+) badfree=(\d+) corrupt=(\d+)", r.out, re.M)
            if mem:
                live, bad_free, corrupt = int(mem.group(1)), int(mem.group(2)), int(mem.group(3))
                if live > 0:
                    res.status, res.mem_unknown = "FAIL", True
                    info.append("memory leak: %d allocation(s) never freed" % live)
                if bad_free:
                    res.status, res.mem_unknown = "FAIL", True
                    info.append("invalid or double free (%d)" % bad_free)
                if corrupt:
                    res.status, res.mem_unknown = "FAIL", True
                    info.append("heap buffer overflow/underflow detected (%d block(s) with a damaged guard zone)" % corrupt)
            bt_names = set(re.findall(r"^@@(?:BADFREEFN|LEAKFN|CORRUPTFN) (ft_\w+)", r.out, re.M))
            if bt_names and res.mem_unknown:
                res.mem |= bt_names
                res.mem_unknown = False
                info.append("in " + ", ".join(sorted(bt_names)))
            if "LeakSanitizer" in r.err:
                res.status = "FAIL"
                info.append("memory leak: " + first_line_with(r.err, "SUMMARY: AddressSanitizer", 90))
                mm = re.search(r" in (ft_\w+)", first_line_with(r.err, r"^\s*#\d+ .* in ft_"))
                if mm:
                    res.mem.add(mm.group(1))
                    info.append("allocated in: " + mm.group(1))
                else:
                    res.mem_unknown = True
            elif "ERROR: AddressSanitizer" in r.err:
                res.status = "FAIL"
                info.append(first_line_with(r.err, "ERROR: AddressSanitizer", 100))
                fns = frames_funcs(r.err)
                if fns:
                    res.mem |= fns
                else:
                    res.mem_unknown = True
        if ub_lines is not None:
            for l in r.err.splitlines():
                if "runtime error" in l:
                    ub_lines.append(re.sub(r"^.*?/?(ft_\w+\.c:\d+):\d+: runtime error: ", r"\1: ", l)[:110])
        res.info = "\n".join(info)
        return res

    if build_fail or hres.rc != 0:
        why = ("could not compile: " + " ".join(build_fail)) if build_fail else first_line_with(hres.err, "error|undefined")
        add("REQ", "behaviour tests", "SKIP", "could not build the test program (fix the gate errors above first)\n" + why)
    else:
        behaviour_ran = True
        env = make_env(10 if quick else 100, lsan)
        ub_lines = []
        for g, tier, label, gfuncs in GROUPS:
            gr = eval_group(harness_bin, env, g, gfuncs, ub_lines)
            if gr.status == "SKIP":
                add(tier, label, "SKIP", gr.skip)
                continue
            info = gr.info
            if gr.status == "FAIL" and (gr.mem or gr.mem_unknown) and not gr.func and not gr.func_unknown and not gr.timed_out:
                info += "\n(memory problem: the moulinette may not notice it, but valgrind / leaks checks in peer evaluation will)"
            add(tier, label, gr.status, info)
            if gr.status != "FAIL":
                continue
            fnames = set(gfuncs) if gr.func_unknown else gr.func
            mnames = set(gfuncs) if gr.mem_unknown else gr.mem
            san_names[g] = fnames | mnames
            if tier == "REQ":
                lost_req.update(fnames)
                if gr.timed_out:
                    lost_req.update(gfuncs)
                lost_risk.update(mnames)
            else:
                lost_risk.update(fnames | mnames)

        say("")
        say(C["DIM"] + "  best-practice behaviour (none of these changes what a function returns)" + C["RST"])
        gr = eval_group(harness_bin, env, "big_size", [])
        if gr.status == "SKIP":
            add("BEST", "ft_strlcpy / ft_strlcat accept sizes above 4 GB (size_t)", "SKIP", gr.skip)
        else:
            add("BEST", "ft_strlcpy / ft_strlcat accept sizes above 4 GB (size_t)", gr.status, ("size parameter is probably 'unsigned int' instead of size_t" if gr.status == "FAIL" else ""))
        if not wrap_ok:
            add("BEST", "malloc failure handled cleanly in all 10 allocating functions", "SKIP", "needs a linker that supports --wrap (GNU ld / lld)")
        else:
            failed_f, finfo = [], []
            for fn in FAIL_FUNCS:
                gr = eval_group(harness_bin, env, "fail_" + fn, [])
                if gr.status == "FAIL":
                    failed_f.append("ft_" + fn)
                    finfo.append("ft_%s: %s" % (fn, " ".join(gr.info.splitlines()[:2])))
            if failed_f:
                add("BEST", "malloc failure handled cleanly (returns NULL, no leak, no crash) in all 10 allocating functions", "FAIL",
                    "problem in: " + " ".join(failed_f) + "\n" + "\n".join(finfo))
            else:
                add("BEST", "malloc failure handled cleanly (returns NULL, no leak, no crash) in all 10 allocating functions", "OK")
        if ubsan:
            ubs = sorted(set(ub_lines))
            add("BEST", "no undefined behaviour detected (UBSan clean across all tests)", "FAIL" if ubs else "OK", "\n".join(ubs[:6]))
        else:
            add("BEST", "no undefined behaviour detected (UBSan)", "SKIP", "UBSan is not available on this platform; run this on Ubuntu for the check")
        if extras:
            nulls = [l.strip() for l in run([harness_bin, "null_inputs"], env=env).out.splitlines() if l.startswith("NULL-unsafe")]
            add("EXTRA", "NOT graded: NULL arguments (libc crashes on NULL too, so only change this if you want to)", "OK" if not nulls else "FAIL",
                "\n".join(n.replace("NULL-unsafe: ", "crashes on: ") for n in nulls[:10]))

    # ============================================================ 8. the real libft.a
    section("8. The archive the moulinette really tests: libft.a built by YOUR Makefile (plain run, no sanitizer)")
    if not behaviour_ran:
        add("REQ", "tests against libft.a", "SKIP", "behaviour tests could not be built")
    elif not (make and os.path.isfile(archive)):
        add("REQ", "tests against libft.a", "SKIP", "libft.a was not built (see the gate errors above)")
    else:
        art = os.path.join(san_dir, "harness_archive")
        ares = link_harness(["-g", "-O0", "-w", "-DNO_WRAP"], [archive], art)
        if ares.rc != 0:
            undefined = sorted(set(re.findall(r"undefined reference to [`'](ft_\w+)'", ares.err)))
            lost_req.update(undefined)
            add("REQ", "harness links against libft.a", "FAIL",
                ("functions missing from libft.a: " + " ".join(undefined)) if undefined else first_line_with(ares.err, "error|undefined"))
        else:
            env = make_env(10 if quick else 40, False)
            bad_groups, info_lines = [], []
            for g, tier, label, gfuncs in GROUPS:
                if tier != "REQ":
                    continue
                gr = eval_group(art, env, g, gfuncs)
                if gr.status != "FAIL":
                    continue
                bad_groups.append(g)
                info_lines.append("%s: %s" % (g, " ".join(gr.info.splitlines()[:2])[:150]))
                if gr.crashed:
                    known = gr.crash_names or san_names.get(g)
                    lost_req.update(known if known else set(gfuncs))
                else:
                    lost_req.update(set(gfuncs) if gr.func_unknown else gr.func)
            add("REQ", "no wrong result and no real crash when linked against libft.a (your Makefile flags, -O0)",
                "FAIL" if bad_groups else "OK", "\n".join(info_lines))

    # ============================================================ result
    section("RESULT")
    gate_fail = [r for r in RESULTS if r["gate"] and r["status"] == "FAIL"]
    req_fail = [r for r in RESULTS if r["tier"] == "REQ" and r["status"] == "FAIL"]
    risk_fail = [r for r in RESULTS if r["tier"] == "RISK" and r["status"] == "FAIL"]
    best_fail = [r for r in RESULTS if r["tier"] == "BEST" and r["status"] == "FAIL"]
    skipped = [r for r in RESULTS if r["status"] == "SKIP" and r["tier"] in ("REQ", "RISK", "BEST")]
    skip_best = [r for r in skipped if r["tier"] == "BEST"]
    skip_req = [r for r in skipped if r["tier"] in ("REQ", "RISK")]
    norm_unverified = any(r["status"] == "WARN" and r["name"].startswith("Norm") for r in RESULTS)

    score = None
    if gate_fail:
        say(" %s%s>> FAIL (gate)%s  - the moulinette gives a final grade of 0 and tests no function." % (C["RED"], C["BLD"], C["RST"]))
        say(" Fix these first:")
        for r in gate_fail:
            say("   - " + r["name"])
    else:
        if behaviour_ran:
            lists_lost = len([f for f in lost_req if f in fl(*LISTS)])
            score = 1 + sum(w for f, w in WEIGHT.items() if f not in lost_req)
            score += int(round(10.0 * (len(LISTS) - lists_lost) / len(LISTS)))
            risk_only = set(lost_risk) - lost_req
            exposure = sum(WEIGHT.get(f, 0) for f in risk_only) + (10.0 * len([f for f in risk_only if f in fl(*LISTS)]) / len(LISTS))
            say(" %sprojected moulinette score: %d/100%s  (estimate from the weights in a real trace; the real tests are private)" % (C["BLD"], score, C["RST"]))
            if lost_req:
                say(" points lost in: %s" % " ".join(sorted(lost_req)))
            if exposure:
                say(" more points at risk from edge cases (not proven in a trace): up to %d" % round(exposure))
            say("")
            if score >= pass_mark:
                say(" %s%s>> OK%s  - passing grade expected (score %d >= pass mark %d)%s" % (
                    C["GRN"], C["BLD"], C["RST"], score, pass_mark, "" if not skip_req else " (provisional: %d check(s) could not run here)" % len(skip_req)))
                if norm_unverified:
                    say("    Norm was NOT verified (norminette missing). A Norm error is a gate failure, so run it before you submit.")
                if score == 100 and not req_fail and not risk_fail and not best_fail:
                    if skip_best:
                        say(" %s%s>> OUTSTANDING PROJECT STANDARDS (provisional)%s  - everything that could run here passed." % (C["CYN"], C["BLD"], C["RST"]))
                        say("    Not checked on this device, so confirm on Ubuntu for the full verdict:")
                        for r in skip_best:
                            say("      - " + r["name"])
                    else:
                        say(" %s%s>> OUTSTANDING PROJECT STANDARDS%s  - full marks expected, no risk items, every best-practice check passed." % (C["CYN"], C["BLD"], C["RST"]))
                else:
                    todo = []
                    if score < 100:
                        todo.append("full marks (fix the failing required checks above)")
                    todo += [r["name"] for r in risk_fail]
                    todo += [r["name"] for r in best_fail]
                    say(" %s>> Not yet at outstanding project standards.%s Remaining:" % (C["YLW"], C["RST"]))
                    for t in todo:
                        say("   - " + t)
            else:
                say(" %s%s>> FAIL%s  - projected %d is below the pass mark %d. Fix the [FAIL] items above." % (C["RED"], C["BLD"], C["RST"], score, pass_mark))
        else:
            say(" %s>> Gate checks passed, but behaviour tests could not run on this device,%s so no score is projected." % (C["YLW"], C["RST"]))
            for r in req_fail:
                say("   - " + r["name"])
    say("")
    say(C["DIM"] + " The gate stage is copied from two real traces: each file compiled alone, norminette, make/clean/fclean/rebuild." + C["RST"])
    say(C["DIM"] + " Function tests are my own strict suite, not the moulinette's private tests, so treat the score as an estimate." + C["RST"])
    say(C["DIM"] + " 80 is the usual pass mark; use --pass-mark N if your project page says otherwise." + C["RST"])

    for d in (os.getcwd(), os.path.expanduser("~"), work):
        try:
            rp = os.path.join(d, "libft_report.txt")
            with open(rp, "w") as fh:
                fh.write("\n".join(LOG) + "\n")
            print("report saved to: " + rp)
            break
        except Exception:
            continue
    if keep:
        print("work dir kept: " + work)
    else:
        shutil.rmtree(work, ignore_errors=True)
    if gate_fail:
        return 1
    if score is not None:
        return 0 if score >= pass_mark else 1
    return 0 if not req_fail else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
