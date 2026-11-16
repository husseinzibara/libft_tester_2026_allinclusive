/* harness.c - libft test groups (portable: Linux, Android/Termux, iSH).
 * Run one group per process:  ./harness <group>
 * Prints machine-readable lines starting with "@@" which run.py interprets.
 *
 * Build modes (chosen by run.py):
 *   default      : malloc/free are wrapped (-Wl,--wrap=malloc,--wrap=free) to count
 *                  allocations, record sizes and inject failures; the real allocator
 *                  (e.g. AddressSanitizer's) does the work.
 *   -DGUARD_ALLOC: additionally replace the allocator with a built-in guard-page
 *                  allocator (finds overreads, overflows, invalid/double frees, and fills
 *                  new memory with 0xCD) for platforms without sanitizers.
 *   -DNO_WRAP    : linker cannot wrap; allocation tracking and failure injection are
 *                  disabled (those groups report @@SKIP).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/mman.h>
#ifndef MAP_ANONYMOUS
# define MAP_ANONYMOUS MAP_ANON
#endif
#include <signal.h>
#if defined(__GLIBC__)
# include <execinfo.h>
# include <dlfcn.h>
# define HAVE_BT 1
#endif
#if defined(__SANITIZE_ADDRESS__)
# define ASAN_BUILD 1
#elif defined(__has_feature)
# if __has_feature(address_sanitizer)
#  define ASAN_BUILD 1
# endif
#endif

/* Name which ft_ function is on the stack (glibc only; elsewhere the runner blames the whole group). */
#ifdef HAVE_BT
static const char *ft_name_of(void *addr)
{
    Dl_info di;
    if (addr && dladdr(addr, &di) && di.dli_sname && !strncmp(di.dli_sname, "ft_", 3)) return di.dli_sname;
    return NULL;
}
static void report_bt(const char *tag)
{
    void *bt[14]; int n = backtrace(bt, 14);
    for (int i = 0; i < n; i++) { const char *nm = ft_name_of(bt[i]); if (nm) { dprintf(1, "@@%s %s\n", tag, nm); return; } }
}
static void crash_handler(int sig)
{
    void *bt[16]; int n = backtrace(bt, 16);
    for (int i = 0; i < n; i++) { const char *nm = ft_name_of(bt[i]); if (nm) dprintf(1, "@@CRASHFN %s\n", nm); }
    dprintf(1, "@@CRASH %d\n", sig);
    _exit(128 + sig);
}
#else
# define report_bt(tag) ((void)0)
#endif

typedef struct s_list { void *content; struct s_list *next; } t_list;
int ft_atoi(const char*); void ft_bzero(void*,size_t); void *ft_calloc(size_t,size_t);
int ft_isalnum(int); int ft_isalpha(int); int ft_isascii(int); int ft_isdigit(int); int ft_isprint(int);
char *ft_itoa(int); void *ft_memchr(const void*,int,size_t); int ft_memcmp(const void*,const void*,size_t);
void *ft_memcpy(void*,const void*,size_t); void *ft_memmove(void*,const void*,size_t); void *ft_memset(void*,int,size_t);
void ft_putchar_fd(char,int); void ft_putendl_fd(char*,int); void ft_putnbr_fd(int,int); void ft_putstr_fd(char*,int);
char **ft_split(const char*,char); char *ft_strchr(const char*,int); char *ft_strdup(const char*);
void ft_striteri(char*,void(*)(unsigned int,char*)); char *ft_strjoin(const char*,const char*);
size_t ft_strlcat(char*,const char*,size_t); size_t ft_strlcpy(char*,const char*,size_t); size_t ft_strlen(const char*);
char *ft_strmapi(const char*,char(*)(unsigned int,char)); int ft_strncmp(const char*,const char*,size_t);
char *ft_strnstr(const char*,const char*,size_t); char *ft_strrchr(const char*,int);
char *ft_strtrim(const char*,const char*); char *ft_substr(const char*,unsigned int,size_t);
int ft_tolower(int); int ft_toupper(int);
t_list *ft_lstnew(void*); void ft_lstadd_front(t_list**,t_list*); int ft_lstsize(t_list*); t_list *ft_lstlast(t_list*);
void ft_lstadd_back(t_list**,t_list*); void ft_lstdelone(t_list*,void(*)(void*)); void ft_lstclear(t_list**,void(*)(void*));
void ft_lstiter(t_list*,void(*)(void*)); t_list *ft_lstmap(t_list*,void*(*)(void*),void(*)(void*));

/* ======================= allocation layer ======================= */
#ifndef NO_WRAP
# define HAVE_TRACK 1
void *__real_malloc(size_t);
void __real_free(void *);

typedef struct { void *p; size_t size; char *base; size_t maplen; void *caller; } ent_t;
# define REG_CAP (1u << 17)
# define TOMB ((void *)1)
static ent_t reg[REG_CAP];
static long g_live, g_badfree, g_corrupt, g_count, g_fail_at;

static size_t hidx(void *p) { return (size_t)((((uintptr_t)p >> 3) * 2654435761u) & (REG_CAP - 1)); }
static ent_t *reg_find(void *p)
{
    size_t i = hidx(p);
    for (size_t n = 0; n < REG_CAP; n++, i = (i + 1) & (REG_CAP - 1)) {
        if (reg[i].p == NULL) return NULL;
        if (reg[i].p == p) return &reg[i];
    }
    return NULL;
}
static void reg_add(void *p, size_t size, char *base, size_t maplen, void *caller)
{
    size_t i = hidx(p);
    for (size_t n = 0; n < REG_CAP; n++, i = (i + 1) & (REG_CAP - 1)) {
        if (reg[i].p == NULL || reg[i].p == TOMB) {
            reg[i].p = p; reg[i].size = size; reg[i].base = base; reg[i].maplen = maplen; reg[i].caller = caller; g_live++;
            return;
        }
    }
    fprintf(stderr, "harness: allocation registry full\n"); _exit(99);
}

# ifdef GUARD_ALLOC
static size_t pagesz;
static void *galloc(size_t size, size_t align, void *caller)
{
    if (!pagesz) pagesz = (size_t)sysconf(_SC_PAGESIZE);
    if (size > SIZE_MAX / 4) { errno = ENOMEM; return NULL; }
    size_t eff = size ? size : 1;
    size_t data = (eff + pagesz - 1) / pagesz * pagesz;
    size_t maplen = data + pagesz;
    char *base = mmap(NULL, maplen, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == (char *)MAP_FAILED) return NULL;
    if (mprotect(base + data, pagesz, PROT_NONE) != 0) { munmap(base, maplen); return NULL; }
    char *end = base + data, *p = end - eff;
    if (align > 1) p = (char *)((uintptr_t)p & ~(uintptr_t)(align - 1));
    memset(base, 0xA5, (size_t)(p - base));                 /* front canary */
    memset(p + eff, 0xA5, (size_t)(end - (p + eff)));       /* tail canary  */
    memset(p, 0xCD, eff);                                   /* garbage: exposes missing init / terminator */
    reg_add(p, size, base, maplen, caller);
    return p;
}
static void gfree(ent_t *e)
{
    char *p = e->p, *end = e->base + e->maplen - pagesz;
    size_t eff = e->size ? e->size : 1;
    int bad_ = 0;
    for (char *q = e->base; q < p; q++) if ((unsigned char)*q != 0xA5) { bad_ = 1; break; }
    for (char *q = p + eff; !bad_ && q < end; q++) if ((unsigned char)*q != 0xA5) { bad_ = 1; break; }
    if (bad_) {
        g_corrupt++;
#ifdef HAVE_BT
        { const char *nm = ft_name_of(e->caller); if (nm) dprintf(1, "@@CORRUPTFN %s\n", nm); }
#endif
    }
    munmap(e->base, e->maplen);
}
# endif

void *__wrap_malloc(size_t n)
{
    void *caller = __builtin_return_address(0);
    g_count++;
    if (g_fail_at && g_count == g_fail_at) return NULL;
# ifdef GUARD_ALLOC
    return galloc(n, sizeof(void *) > 4 ? 16 : 8, caller);
# else
    void *p = __real_malloc(n);
    if (p) reg_add(p, n, NULL, 0, caller);
    return p;
# endif
}
void __wrap_free(void *p)
{
    if (!p) return;
    ent_t *e = reg_find(p);
    if (!e) { g_badfree++; if (g_badfree <= 3) report_bt("BADFREEFN"); return; }   /* invalid or double free: do not touch */
# ifdef GUARD_ALLOC
    gfree(e);
# else
    __real_free(p);
# endif
    e->p = TOMB; g_live--;
}
/* exact-size buffer for test INPUT strings: an overread by even one byte is detected */
static void *xmalloc(size_t n)
{
# if defined(GUARD_ALLOC)
    return galloc(n, 1, NULL);
# else
    void *p = __real_malloc(n ? n : 1);      /* bypasses the failure-injection counter */
    if (p) reg_add(p, n, NULL, 0, NULL);
    return p;
# endif
}
static int alloc_size(void *p, size_t *out) { ent_t *e = reg_find(p); if (!e) return 0; *out = e->size; return 1; }
#else /* NO_WRAP */
# define HAVE_TRACK 0
static long g_live, g_badfree, g_corrupt, g_count, g_fail_at;
static void *xmalloc(size_t n) { return malloc(n ? n : 1); }
static int alloc_size(void *p, size_t *out) { (void)p; (void)out; return 0; }
#endif

/* ======================= helpers ======================= */
static long pass, fail, shown;
static int skipped;
static char skipmsg[160];
#define CHECK(cond) do { if (cond) pass++; else { fail++; if (shown++ < 80) printf("FAIL line %d: %s\n", __LINE__, #cond); } } while (0)
#define CHECKF(fn, cond) do { if (cond) pass++; else { fail++; if (shown++ < 80) printf("FAIL line %d: subject=%s %s\n", __LINE__, fn, #cond); } } while (0)
static int sgn(int x) { return (x > 0) - (x < 0); }
static unsigned rs = 12345;
static unsigned rnd(void) { rs = rs * 1103515245u + 12345u; return (rs >> 8) & 0xffffff; }
static int fuzz_pct = 100;
static long scaled(long n) { long v = n * fuzz_pct / 100; return v < 1 ? 1 : v; }
static char *H(const char *s) { size_t l = strlen(s); char *p = xmalloc(l + 1); memcpy(p, s, l + 1); return p; }
static char *RS(int maxlen, const char *alpha)
{
    int l = (int)(rnd() % (unsigned)(maxlen + 1)); size_t a = strlen(alpha);
    char *p = xmalloc((size_t)l + 1);
    for (int i = 0; i < l; i++) p[i] = alpha[rnd() % a];
    p[l] = 0; return p;
}
static char *dupstr(const char *s) { return H(s); }
static char *dupn(const char *s, size_t n) { char *p = xmalloc(n + 1); memcpy(p, s, n); p[n] = 0; return p; }
static size_t ref_lcpy(char *d, const char *s, size_t n) { size_t l = strlen(s); if (n) { size_t c = l >= n ? n - 1 : l; memcpy(d, s, c); d[c] = 0; } return l; }
static size_t ref_lcat(char *d, const char *s, size_t n)
{
    size_t dl = 0; while (dl < n && d[dl]) dl++;
    size_t sl = strlen(s); if (dl == n) return n + sl;
    size_t i = 0; while (s[i] && dl + i + 1 < n) { d[dl + i] = s[i]; i++; }
    d[dl + i] = 0; return dl + sl;
}
static char *ref_nstr(const char *b, const char *l, size_t n)
{
    size_t ll = strlen(l); if (!ll) return (char *)b;
    for (size_t i = 0; b[i] && i < n; i++) { if (i + ll > n) break; if (!strncmp(b + i, l, ll)) return (char *)b + i; }
    return NULL;
}
static void up(unsigned i, char *c) { *c = (char)(*c + (i % 3)); }
static char mp(unsigned i, char c) { return (char)(c + (i % 3)); }
static void del(void *p) { free(p); }
static void noop(void *p) { (void)p; }
static void *dupf(void *p) { return dupstr(p); }
static void free_split(void *p) { char **v = p; if (!v) return; for (int i = 0; v[i]; i++) free(v[i]); free(v); }
static void *addone(void *p) { int *r = malloc(sizeof(int)); *r = *(int *)p + 1; return r; }
static void SKIP(const char *why) { skipped = 1; snprintf(skipmsg, sizeof skipmsg, "%s", why); }

/* libftTester-style "MOK": the block must be at least as big as needed and in the same
 * malloc size class (modelled on glibc: 24, 40, 56 ... usable bytes). */
static int cls(size_t n) { return n <= 24 ? 0 : (int)((n - 9) / 16); }
static void mok(void *p, size_t need, int line, const char *what)
{
    size_t got;
    if (!HAVE_TRACK) return;
    if (!alloc_size(p, &got)) { fail++; if (shown++ < 80) printf("FAIL line %d: %s: block not tracked\n", line, what); return; }
    if (got >= need && cls(got) == cls(need)) pass++;
    else { fail++; if (shown++ < 80) printf("FAIL line %d: %s allocated %lu bytes, needs %lu\n", line, what, (unsigned long)got, (unsigned long)need); }
}
#define MOK(p, need) mok((p), (need), __LINE__, #p)
#define MOKF(fn, p, need) mok((p), (need), __LINE__, fn)

/* ======================= REQUIRED GROUPS ======================= */
static void g_ctype(void)
{
    for (int c = -300; c <= 300; c++) {
        int ok = (c >= 0 && c <= 255);
        CHECK(!!ft_isalpha(c) == (ok && isalpha(c))); CHECK(!!ft_isdigit(c) == (ok && isdigit(c)));
        CHECK(!!ft_isalnum(c) == (ok && isalnum(c))); CHECK(!!ft_isprint(c) == (ok && isprint(c)));
        CHECK(!!ft_isascii(c) == (c >= 0 && c <= 127));
        if (ok) { CHECK(ft_toupper(c) == toupper(c)); CHECK(ft_tolower(c) == tolower(c)); }
    }
}

static void g_mem(void)
{
    for (long it = 0; it < scaled(20000); it++) {
        size_t n = rnd() % 40;
        unsigned char *a = xmalloc(n), *b = xmalloc(n), *x = xmalloc(n), *y = xmalloc(n);
        for (size_t i = 0; i < n; i++) { a[i] = (unsigned char)rnd(); b[i] = (unsigned char)rnd(); }
        if (rnd() % 3 == 0) memcpy(b, a, n);
        if (n && rnd() % 3 == 0) b[rnd() % n] ^= 0x80;
        CHECK(sgn(ft_memcmp(a, b, n)) == sgn(memcmp(a, b, n)));
        int c = (int)(rnd() % 256); if (rnd() % 4 == 0) c += 256 * (int)(rnd() % 3);
        CHECK(ft_memchr(a, c, n) == memchr(a, c, n));
        memcpy(x, a, n); memcpy(y, a, n); ft_memset(x, c, n); memset(y, c, n); CHECKF("ft_memset", !memcmp(x, y, n));
        ft_bzero(x, n); memset(y, 0, n); CHECKF("ft_bzero", !memcmp(x, y, n));
        memcpy(x, a, n); ft_memcpy(x, b, n); CHECKF("ft_memcpy", !memcmp(x, b, n));
        free(a); free(b); free(x); free(y);
        unsigned char u[64], v[64]; for (size_t i = 0; i < 64; i++) u[i] = v[i] = (unsigned char)rnd();
        size_t d = rnd() % 32, s = rnd() % 32, m = rnd() % 32;
        ft_memmove(u + d, u + s, m); memmove(v + d, v + s, m); CHECKF("ft_memmove", !memcmp(u, v, 64));
    }
    { unsigned char z[4] = {1, 2, 3, 4}; CHECK(ft_memmove(z, z, 4) == z); CHECK(ft_memmove(z, z + 1, 0) == z); CHECK(ft_memcpy(z, z, 0) == z); }
    { unsigned char a[2] = {0x80, 0}, b[2] = {0x01, 0}; CHECK(ft_memcmp(a, b, 1) > 0); CHECK(ft_memcmp(b, a, 1) < 0); }
    { char dest[100]; memset(dest, 'A', 100); CHECKF("ft_memcpy", ft_memcpy(dest, "coucou", 0) == dest && dest[0] == 'A');
      CHECKF("ft_memcpy", ft_memcpy(dest, NULL, 0) == dest && dest[0] == 'A'); }
    { char t[100]; memset(t, 'A', 100); ft_bzero(t, 0); CHECKF("ft_bzero", t[0] == 'A'); ft_bzero(t, 42); int i = 0; while (i < 100 && t[i] == 0) i++; CHECKF("ft_bzero", i == 42 && t[42] == 'A');
      memset(t, 0, 100); ft_memset(t, 'A', 0); CHECKF("ft_memset", t[0] == 0); ft_memset(t, 'A', 42); i = 0; while (i < 100 && t[i] == 'A') i++; CHECKF("ft_memset", i == 42 && t[42] == 0); }
}

static void g_str(void)
{
    char alpha[] = "ab c,\t";
    for (long it = 0; it < scaled(20000); it++) {
        char *s = RS(14, alpha), *t = RS(14, alpha);
        char *hs = H(s), *ht = H(t);
        CHECK(ft_strlen(hs) == strlen(s));
        int c = "ab c,\t\0x"[rnd() % 8]; if (rnd() % 5 == 0) c += 256;
        CHECK(ft_strchr(hs, c) == strchr(hs, c));
        CHECK(ft_strrchr(hs, c) == strrchr(hs, c));
        size_t n = rnd() % 20;
        CHECK(sgn(ft_strncmp(hs, ht, n)) == sgn(strncmp(s, t, n)));
        CHECK(sgn(ft_strncmp(hs, ht, SIZE_MAX)) == sgn(strcmp(s, t)));
        size_t cl = rnd() % 24; char d1[40], d2[40];
        memset(d1, 'Z', 40); memset(d2, 'Z', 40);
        CHECK(ft_strlcpy(d1, ht, cl) == ref_lcpy(d2, t, cl)); CHECKF("ft_strlcpy", !memcmp(d1, d2, 40));
        memset(d1, 'Z', 40); memset(d2, 'Z', 40);
        CHECK(ft_strlcpy(d1, ht, SIZE_MAX) == ref_lcpy(d2, t, SIZE_MAX)); CHECKF("ft_strlcpy", !memcmp(d1, d2, 40));
        memset(d1, 0, 40); memset(d2, 0, 40); strcpy(d1, s); strcpy(d2, s);
        size_t k = rnd() % 30; CHECK(ft_strlcat(d1, ht, k) == ref_lcat(d2, t, k)); CHECKF("ft_strlcat", !memcmp(d1, d2, 40));
        memset(d1, 0, 40); memset(d2, 0, 40); strcpy(d1, s); strcpy(d2, s);
        CHECK(ft_strlcat(d1, ht, SIZE_MAX) == ref_lcat(d2, t, SIZE_MAX)); CHECKF("ft_strlcat", !memcmp(d1, d2, 40));
        memset(d1, 'Q', 40); memset(d2, 'Q', 40); d1[39] = d2[39] = 0; size_t k2 = rnd() % 10;
        CHECK(ft_strlcat(d1, ht, k2) == ref_lcat(d2, t, k2)); CHECKF("ft_strlcat", !memcmp(d1, d2, 40));
        size_t ln = rnd() % 20; char *hs2 = H(s);
        CHECK(ft_strnstr(hs2, ht, ln) == ref_nstr(hs2, t, ln));
        CHECK(ft_strnstr(hs2, ht, SIZE_MAX) == ref_nstr(hs2, t, SIZE_MAX));
        char *du = ft_strdup(hs); CHECKF("ft_strdup", du && !strcmp(du, s) && du != hs); free(du);
        free(s); free(t); free(hs); free(ht); free(hs2);
    }
    /* strings containing bytes above 127 (strncmp must compare as unsigned char, strchr must cast) */
    for (long it = 0; it < scaled(5000); it++) {
        size_t la = rnd() % 8, lb = (rnd() % 3 == 0) ? la : rnd() % 8;
        char *a = xmalloc(la + 1), *b = xmalloc(lb + 1);
        for (size_t i = 0; i < la; i++) a[i] = (char)(1 + rnd() % 255);
        if (lb == la && rnd() % 2) memcpy(b, a, la); else for (size_t i = 0; i < lb; i++) b[i] = (char)(1 + rnd() % 255);
        a[la] = b[lb] = 0;
        size_t n = rnd() % 10;
        CHECK(sgn(ft_strncmp(a, b, n)) == sgn(strncmp(a, b, n)));
        CHECKF("ft_memcmp", sgn(ft_memcmp(a, b, la < lb ? la : lb)) == sgn(memcmp(a, b, la < lb ? la : lb)));
        int c = (int)(rnd() % 256); CHECK(ft_strchr(a, c) == strchr(a, c)); CHECK(ft_strrchr(a, c) == strrchr(a, c));
        free(a); free(b);
    }
    CHECK(ft_strncmp("a", "b", 0) == 0); CHECK(ft_strncmp("ab\0x", "ab\0y", 4) == 0); CHECK(ft_strncmp("\200", "a", 1) > 0);
    CHECK(ft_strlen("") == 0); CHECK(ft_strlen("123") == 3);
}

static void g_atoi(void)
{
    for (long it = 0; it < scaled(20000); it++) {
        char buf[64]; const char *ws[] = {"", " ", "\t\n", "\v\f\r  "}; const char *sg[] = {"", "+", "-"};
        int64_t v = (int64_t)(int32_t)(((uint32_t)rnd() << 8) ^ (uint32_t)rnd());
        if (rnd() % 10 == 0) v = (rnd() % 2) ? INT_MAX : INT_MIN;
        if (v == INT_MIN) snprintf(buf, sizeof buf, "%s-2147483648", ws[rnd() % 4]);
        else snprintf(buf, sizeof buf, "%s%s%lld", ws[rnd() % 4], sg[v < 0 ? 2 : (rnd() % 2 ? 1 : 0)], (long long)(v < 0 ? -v : v));
        char *hb = H(buf); CHECK(ft_atoi(hb) == atoi(hb)); free(hb);
    }
    struct { const char *s; int exp; } k[] = {
        {"\t\n\v\f\r" "1", 1}, {"\t\n\v\f\r" "a1", 0}, {"\t\n\v\f\r" "--1", 0}, {"\t\n\v\f\r" "++1", 0},
        {"\t\n\v\f\r" "+1", 1}, {"\t\n\v\f\r" "-1", -1}, {"\t\n\v\f\r" "0", 0}, {"\t\n\v\f\r" "+42lyon", 42},
        {"\t\n\v\f\r" "+101", 101}, {"\t\n\v\f\r" "2147483647", INT_MAX}, {"\t\n\v\f\r" "-2147483648", INT_MIN},
        {"-+42", 0}, {"+-42", 0}, {"+\t\n\v\f\r" "42", 0}, {"-\t\n\v\f\r" "42", 0}, {"1\t\n\v\f\r" "42", 1}, {"-1\t\n\v\f\r" "42", -1},
        {"", 0}, {"+", 0}, {"-", 0}, {" ", 0}, {"000123", 123}, {"-0", 0}, {"12 34", 12}, {"abc", 0}, {"2147483647", INT_MAX}, {"-2147483648", INT_MIN},
    };
    for (unsigned i = 0; i < sizeof k / sizeof *k; i++) { char *h = H(k[i].s); CHECK(ft_atoi(h) == k[i].exp); free(h); }
}

static void g_itoa(void)
{
    int sp[] = {0, 1, -1, 9, 10, -9, -10, 99, 100, -100, INT_MAX, INT_MIN, INT_MAX - 1, INT_MIN + 1, 1000000000, -1000000000, 42};
    for (unsigned i = 0; i < sizeof sp / sizeof *sp; i++) { char e[24]; snprintf(e, sizeof e, "%d", sp[i]); char *r = ft_itoa(sp[i]); CHECK(r && !strcmp(r, e)); free(r); }
    for (long it = 0; it < scaled(20000); it++) { int v = (int)(((uint32_t)rnd() << 8) ^ (uint32_t)rnd()); char e[24]; snprintf(e, sizeof e, "%d", v); char *r = ft_itoa(v); CHECK(r && !strcmp(r, e)); free(r); }
}

static void g_calloc(void)
{
    for (int it = 0; it < 500; it++) {
        size_t a = rnd() % 20, b = rnd() % 20; unsigned char *p = ft_calloc(a, b);
        CHECK(p != NULL || a * b == 0);
        for (size_t i = 0; p && i < a * b; i++) CHECK(p[i] == 0);
        free(p);
    }
    unsigned char *q = ft_calloc(2, 2); CHECK(q && !q[0] && !q[1] && !q[2] && !q[3]); free(q);
}

static void g_calloc_edges(void)
{
    void *p;
    p = ft_calloc(0, 0); CHECK(p != NULL); free(p);
    p = ft_calloc(0, 5); CHECK(p != NULL); free(p);
    p = ft_calloc(5, 0); CHECK(p != NULL); free(p);
    p = ft_calloc(0, (size_t)-5); CHECK(p != NULL); free(p);
    p = ft_calloc((size_t)-5, 0); CHECK(p != NULL); free(p);
    CHECK(ft_calloc(SIZE_MAX, SIZE_MAX) == NULL);
    CHECK(ft_calloc(SIZE_MAX, 2) == NULL);
    CHECK(ft_calloc(SIZE_MAX / 2 + 1, 2) == NULL);
    CHECK(ft_calloc(2, SIZE_MAX / 2 + 1) == NULL);
    CHECK(ft_calloc((size_t)INT_MAX, (size_t)INT_MAX) == NULL);      /* valid product, impossible allocation (64-bit) */
    CHECK(ft_calloc((size_t)INT_MIN, (size_t)INT_MIN) == NULL);
    CHECK(ft_calloc((size_t)-5, (size_t)-5) == NULL);
    CHECK(ft_calloc(3, (size_t)-5) == NULL);
    CHECK(ft_calloc((size_t)-5, 3) == NULL);
}

static void g_substr_join_trim(void)
{
    char alpha[] = "ab c,\t";
    for (long it = 0; it < scaled(20000); it++) {
        char *s = RS(12, alpha), *hs = H(s); unsigned st = rnd() % 16; size_t ln = (rnd() % 5 == 0) ? SIZE_MAX : rnd() % 16;
        char *r = ft_substr(hs, st, ln); size_t sl = strlen(s); size_t o = st > sl ? sl : st; size_t m = sl - o; if (ln < m) m = ln;
        CHECKF("ft_substr", r && strlen(r) == m && !memcmp(r, s + o, m)); free(r);
        char *t = RS(12, alpha), *ht = H(t); r = ft_strjoin(hs, ht); char *e = xmalloc(sl + strlen(t) + 1); strcpy(e, s); strcat(e, t);
        CHECKF("ft_strjoin", r && !strcmp(r, e)); free(r); free(e);
        char *set = RS(4, "a ,"); char *hset = H(set); r = ft_strtrim(hs, hset);
        size_t a = 0, b = sl; while (a < b && s[a] && strchr(set, s[a])) a++; while (b > a && s[b - 1] && strchr(set, s[b - 1])) b--;
        CHECKF("ft_strtrim", r && strlen(r) == b - a && !memcmp(r, s + a, b - a)); free(r);
        free(s); free(hs); free(t); free(ht); free(set); free(hset);
    }
    char *r = ft_strtrim("  a b  ", " "); CHECKF("ft_strtrim", r && !strcmp(r, "a b")); free(r);
    r = ft_strtrim("xxaxx", "x"); CHECKF("ft_strtrim", r && !strcmp(r, "a")); free(r);
    r = ft_strtrim("xxxx", "x"); CHECKF("ft_strtrim", r && !*r); free(r);
    r = ft_strtrim("abc", ""); CHECKF("ft_strtrim", r && !strcmp(r, "abc")); free(r);
    r = ft_strtrim("ababa", "a"); CHECKF("ft_strtrim", r && !strcmp(r, "bab")); free(r);
    r = ft_strtrim("abcdba", "acb"); CHECKF("ft_strtrim", r && !strcmp(r, "d")); free(r);
    r = ft_strtrim("   xxxtripouille   xxx", " x"); CHECKF("ft_strtrim", r && !strcmp(r, "tripouille")); free(r);
    r = ft_substr("hello", 10, 3); CHECKF("ft_substr", r && !*r); free(r);
    r = ft_substr("hello", 2, SIZE_MAX); CHECKF("ft_substr", r && !strcmp(r, "llo")); free(r);
    r = ft_substr("0123456789", 9, 10); CHECKF("ft_substr", r && !strcmp(r, "9")); free(r);
    r = ft_substr("42", 0, 0); CHECKF("ft_substr", r && !*r); free(r);
    r = ft_strjoin("", ""); CHECKF("ft_strjoin", r && !*r); free(r);
}

static void g_split(void)
{
    for (long it = 0; it < scaled(20000); it++) {
        char *s = RS(16, "ab, "), *hs = H(s); char dch = ",ab "[rnd() % 4]; char **v = ft_split(hs, dch);
        CHECK(v != NULL); if (!v) { free(s); free(hs); continue; }
        char *c = H(s); size_t i = 0, w = 0; char **ex = xmalloc(20 * sizeof(char *));
        while (c[i]) { if (c[i] == dch) { i++; continue; } size_t j = i; while (c[j] && c[j] != dch) j++; ex[w] = dupn(c + i, j - i); w++; i = j; }
        size_t k = 0; for (; v[k]; k++) { CHECK(k < w && !strcmp(v[k], ex[k])); free(v[k]); } CHECK(k == w);
        free(v); for (size_t q = 0; q < w; q++) free(ex[q]); free(ex); free(c); free(s); free(hs);
    }
    char **v = ft_split("abc", '\0'); CHECK(v != NULL); if (v) { CHECK(v[0] && !strcmp(v[0], "abc") && !v[1]); free_split(v); }
    v = ft_split("", ' '); CHECK(v && !v[0]); free(v);
    v = ft_split("    ", ' '); CHECK(v && !v[0]); free(v);
    { char *e = xmalloc(1); *e = 0; v = ft_split(e, '\0'); CHECK(v && !v[0]); free(v); free(e); }   /* no read past the terminator */
    v = ft_split("  tripouille  42  ", ' '); CHECK(v && v[0] && !strcmp(v[0], "tripouille") && v[1] && !strcmp(v[1], "42") && !v[2]); free_split(v);
    v = ft_split("--1-2--3---4----5-----42", '-');
    CHECK(v && v[0] && !strcmp(v[0], "1") && !strcmp(v[1], "2") && !strcmp(v[2], "3") && !strcmp(v[3], "4") && !strcmp(v[4], "5") && !strcmp(v[5], "42") && !v[6]); free_split(v);
}

static void g_mapi_iteri(void)
{
    char alpha[] = "ab c,\t";
    for (long it = 0; it < scaled(5000); it++) {
        char *s = RS(12, alpha), *hs = H(s); char *r = ft_strmapi(hs, mp); CHECKF("ft_strmapi", r && strlen(r) == strlen(s));
        for (size_t i = 0; r && i < strlen(s); i++) { CHECKF("ft_strmapi", r[i] == (char)(s[i] + (i % 3))); }
        free(r);
        char *c = H(s); ft_striteri(c, up); for (size_t i = 0; i < strlen(s); i++) { CHECKF("ft_striteri", c[i] == (char)(s[i] + (i % 3))); } free(c); free(s); free(hs);
    }
    char *r = ft_strmapi("", mp); CHECKF("ft_strmapi", r && !*r); free(r);
    char e[] = ""; ft_striteri(e, up); CHECKF("ft_striteri", !*e);
}

static const char *tmpdir_path(void) { const char *t = getenv("LIBFT_TESTER_TMP"); return t && *t ? t : "."; }
static void g_put_fd(void)
{
    int vals[] = {0, 1, -1, 42, -42, INT_MAX, INT_MIN, 100, -100, 1000000, 10};
    char path[512]; snprintf(path, sizeof path, "%s/libft_put_%ld.txt", tmpdir_path(), (long)getpid());
    for (unsigned i = 0; i < sizeof vals / sizeof *vals; i++) {
        int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644); ft_putnbr_fd(vals[i], fd); close(fd);
        char rd[64] = {0}, e[64]; fd = open(path, O_RDONLY); ssize_t q = read(fd, rd, 63); (void)q; close(fd);
        snprintf(e, sizeof e, "%d", vals[i]); CHECKF("ft_putnbr_fd", !strcmp(rd, e));
    }
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644); ft_putchar_fd('x', fd); ft_putstr_fd("", fd); ft_putendl_fd("", fd); ft_putstr_fd("ab", fd); ft_putendl_fd("42", fd); close(fd);
    char rd[32] = {0}; fd = open(path, O_RDONLY); ssize_t q = read(fd, rd, 31); (void)q; close(fd); CHECKF("ft_putchar_fd", rd[0] == 'x'); CHECKF("ft_putendl_fd", rd[1] == '\n' && !strcmp(rd + 4, "42\n")); CHECKF("ft_putstr_fd", !strncmp(rd + 2, "ab", 2));
    unlink(path);
}

static t_list *mknode(const char *txt, t_list *next)   /* built by hand, so one list bug cannot cascade */
{
    t_list *n = malloc(sizeof(t_list));
    n->content = dupstr(txt); n->next = next;
    return n;
}

static void g_lists(void)
{
    t_list *l = NULL; ft_lstclear(&l, del);
    CHECKF("ft_lstsize", ft_lstsize(NULL) == 0); CHECKF("ft_lstlast", ft_lstlast(NULL) == NULL);

    /* ft_lstnew */
    t_list *n = ft_lstnew(dupstr("a")); CHECKF("ft_lstnew", n && n->next == NULL && !strcmp(n->content, "a"));
    t_list *one = ft_lstnew(NULL); CHECKF("ft_lstnew", one && one->next == NULL && one->content == NULL); ft_lstdelone(one, del);

    /* ft_lstadd_back: onto an empty list, then a 3-node chain onto it (must not be cut) */
    ft_lstadd_back(&l, n); CHECKF("ft_lstadd_back", l == n);
    t_list *chain = mknode("x", mknode("y", mknode("z", NULL)));
    ft_lstadd_back(&l, chain);
    CHECKF("ft_lstadd_back", l->next == chain && chain->next && chain->next->next && !chain->next->next->next);
    while (l) { t_list *nx = l->next; free(l->content); free(l); l = nx; }

    /* ft_lstadd_front on a hand-built list */
    t_list *f = mknode("b", mknode("c", NULL));
    ft_lstadd_front(&f, mknode("a", NULL));
    CHECKF("ft_lstadd_front", f && !strcmp(f->content, "a") && f->next && !strcmp(f->next->content, "b") && f->next->next);

    /* ft_lstsize / ft_lstlast / ft_lstiter on a hand-built list */
    t_list *h = mknode("1", mknode("2", mknode("3", mknode("4", mknode("5", NULL)))));
    CHECKF("ft_lstsize", ft_lstsize(h) == 5);
    CHECKF("ft_lstlast", ft_lstlast(h) == h->next->next->next->next && !strcmp(ft_lstlast(h)->content, "5"));
    ft_lstiter(h, noop);

    /* ft_lstmap */
    t_list *m = ft_lstmap(h, dupf, del);
    int cnt = 0, same = 1;
    for (t_list *a2 = h, *b2 = m; a2 && b2; a2 = a2->next, b2 = b2->next, cnt++)
        if (a2 == b2 || a2->content == b2->content || strcmp(a2->content, b2->content)) same = 0;
    CHECKF("ft_lstmap", cnt == 5 && same && m);
    /* ft_lstclear / ft_lstdelone */
    ft_lstclear(&m, del); CHECKF("ft_lstclear", m == NULL);
    ft_lstclear(&h, del); CHECKF("ft_lstclear", h == NULL);
    ft_lstclear(&f, del); CHECKF("ft_lstclear", f == NULL);
    ft_lstdelone(mknode("solo", NULL), del);

    /* ft_lstmap with int contents */
    int tab[4] = {0, 1, 2, 3};
    t_list *li = malloc(sizeof(t_list)); li->content = &tab[0]; li->next = NULL; t_list *tail = li;
    for (int i = 1; i < 4; i++) { t_list *nd = malloc(sizeof(t_list)); nd->content = &tab[i]; nd->next = NULL; tail->next = nd; tail = nd; }
    t_list *mi = ft_lstmap(li, addone, free); int idx = 0;
    for (t_list *a3 = li, *b3 = mi; a3 && b3; a3 = a3->next, b3 = b3->next, idx++) CHECKF("ft_lstmap", *(int *)a3->content == idx && *(int *)b3->content == idx + 1);
    CHECKF("ft_lstmap", idx == 4); ft_lstclear(&mi, free);
    while (li) { t_list *nx = li->next; free(li); li = nx; }
}

/* libftTester-style allocation size checks ("MOK") */
static void g_alloc_sizes(void)
{
    if (!HAVE_TRACK) { SKIP("linker cannot wrap malloc here"); return; }
    char *s; char **v;
    void *q = ft_calloc(2, 2); MOKF("ft_calloc", q, 4); free(q);
    s = ft_strdup("coucou"); MOKF("ft_strdup", s, 7); free(s);
    s = ft_strdup(""); MOKF("ft_strdup", s, 1); free(s);
    int iv[] = {INT_MAX, INT_MIN, 0, 1, -1, 42, 1000, -999999};
    for (unsigned i = 0; i < sizeof iv / sizeof *iv; i++) { char e[24]; snprintf(e, sizeof e, "%d", iv[i]); s = ft_itoa(iv[i]); MOKF("ft_itoa", s, strlen(e) + 1); free(s); }
    s = ft_strjoin("tripouille", "42"); MOKF("ft_strjoin", s, 13); free(s);
    s = ft_strjoin("", "42"); MOKF("ft_strjoin", s, 3); free(s);
    s = ft_strjoin("42", ""); MOKF("ft_strjoin", s, 3); free(s);
    s = ft_strjoin("", ""); MOKF("ft_strjoin", s, 1); free(s);
    s = ft_strmapi("1234", mp); MOKF("ft_strmapi", s, 5); free(s);
    s = ft_strmapi("", mp); MOKF("ft_strmapi", s, 1); free(s);
    s = ft_substr("tripouille", 0, 42000); MOKF("ft_substr", s, 11); free(s);
    s = ft_substr("tripouille", 1, 1); MOKF("ft_substr", s, 2); free(s);
    s = ft_substr("tripouille", 100, 1); MOKF("ft_substr", s, 1); free(s);
    s = ft_substr("1", 42, 42000000); MOKF("ft_substr", s, 1); free(s);
    s = ft_substr("0123456789", 9, 10); MOKF("ft_substr", s, 2); free(s);
    s = ft_substr("42", 0, 0); MOKF("ft_substr", s, 1); free(s);
    s = ft_substr("BONJOUR LES HARICOTS !", 8, 14); MOKF("ft_substr", s, 15); free(s);
    s = ft_substr("test", 1, 2); MOKF("ft_substr", s, 3); free(s);
    s = ft_strtrim("   xxxtripouille", " x"); MOKF("ft_strtrim", s, 11); free(s);
    s = ft_strtrim("tripouille   xxx", " x"); MOKF("ft_strtrim", s, 11); free(s);
    s = ft_strtrim("   xxxtripouille   xxx", " x"); MOKF("ft_strtrim", s, 11); free(s);
    s = ft_strtrim("   xxx   xxx", " x"); MOKF("ft_strtrim", s, 1); free(s);
    s = ft_strtrim("", "123"); MOKF("ft_strtrim", s, 1); free(s);
    s = ft_strtrim("123", ""); MOKF("ft_strtrim", s, 4); free(s);
    s = ft_strtrim("abcdba", "acb"); MOKF("ft_strtrim", s, 2); free(s);
    s = ft_strtrim("ababa", "a"); MOKF("ft_strtrim", s, 4); free(s);
    t_list *nd = ft_lstnew((void *)0); MOKF("ft_lstnew", nd, sizeof(t_list)); free(nd);
    v = ft_split("  tripouille  42  ", ' '); MOKF("ft_split", v, sizeof(char *) * 3); MOKF("ft_split", v[0], 11); MOKF("ft_split", v[1], 3); free_split(v);
    v = ft_split("chinimala", ' '); MOKF("ft_split", v, sizeof(char *) * 2); free_split(v);
    v = ft_split("", ' '); MOKF("ft_split", v, sizeof(char *)); free_split(v);
    v = ft_split(" Tripouille ", ' '); MOKF("ft_split", v, sizeof(char *) * 2); MOKF("ft_split", v[0], 11); free_split(v);
    v = ft_split("--1-2--3---4----5-----42", '-'); MOKF("ft_split", v, sizeof(char *) * 7); MOKF("ft_split", v[0], 2); MOKF("ft_split", v[5], 3); free_split(v);
    char alpha[] = "ab c,\t";
    for (long it = 0; it < scaled(2000); it++) {
        char *a = RS(12, alpha), *b = RS(12, alpha), *ha = H(a), *hb = H(b);
        unsigned st = rnd() % 16; size_t ln = rnd() % 16, sl = strlen(a), o = st > sl ? sl : st, m = sl - o; if (ln < m) m = ln;
        s = ft_substr(ha, st, ln); MOKF("ft_substr", s, m + 1); free(s);
        s = ft_strjoin(ha, hb); MOKF("ft_strjoin", s, sl + strlen(b) + 1); free(s);
        char *set = RS(3, "a ,"); char *hset = H(set); size_t x = 0, y = sl;
        while (x < y && strchr(set, a[x])) x++;
        while (y > x && strchr(set, a[y - 1])) y--;
        s = ft_strtrim(ha, hset); MOKF("ft_strtrim", s, y - x + 1); free(s);
        free(a); free(b); free(ha); free(hb); free(set); free(hset);
    }
}

/* scenarios taken from the classic edge cases, expressed against reference functions */
static void g_known_cases(void)
{
    const char *H1 = "aaabcabcd";
    struct { const char *h, *n; size_t len; } ns[] = {
        {H1, "aabc", 0}, {H1, "aabc", SIZE_MAX}, {H1, "a", SIZE_MAX}, {H1, "c", SIZE_MAX}, {"", "", SIZE_MAX}, {"", "", 0},
        {"", "coucou", SIZE_MAX}, {H1, "aaabc", 5}, {"", "12345", 5}, {H1, "abcd", 9}, {H1, "cd", 8}, {H1, "a", 1},
        {"1", "a", 1}, {"22", "b", 2}, {"22", "22", 3}, {H1, "", 0}, {H1, "d", 9}, {H1, "d", 8}, {"abc", "abcd", 10}, {"abc", "abc", 2},
    };
    for (unsigned i = 0; i < sizeof ns / sizeof *ns; i++) {
        char *h = H(ns[i].h), *n = H(ns[i].n); CHECK(ft_strnstr(h, n, ns[i].len) == ref_nstr(h, n, ns[i].len)); free(h); free(n);
    }
    struct { const char *a, *b; size_t n; } nc[] = {
        {"t", "", 0}, {"1234", "1235", 3}, {"1234", "1235", 4}, {"1234", "1235", SIZE_MAX}, {"", "", 42}, {"Tripouille", "Tripouille", 42},
        {"Tripouille", "tripouille", 42}, {"Tripouille", "TriPouille", 42}, {"Tripouille", "TripouillE", 42}, {"Tripouille", "TripouilleX", 42},
        {"Tripouille", "Tripouill", 42}, {"", "1", 0}, {"1", "", 0}, {"", "1", 1}, {"1", "", 1}, {"", "", 1}, {"test", "tes\200", 4}, {"test", "tes\326", 4},
    };
    for (unsigned i = 0; i < sizeof nc / sizeof *nc; i++) {
        char *a = H(nc[i].a), *b = H(nc[i].b); CHECK(sgn(ft_strncmp(a, b, nc[i].n)) == sgn(strncmp(a, b, nc[i].n))); free(a); free(b);
    }
    /* strlcpy: every size from 0..9 plus SIZE_MAX, buffer pre-filled with 'A' */
    size_t sizes[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 42, SIZE_MAX};
    for (unsigned i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        char d1[12], d2[12]; memset(d1, 'A', 12); memset(d2, 'A', 12); char *src = H("coucou");
        CHECK(ft_strlcpy(d1, src, sizes[i]) == ref_lcpy(d2, src, sizes[i])); CHECKF("ft_strlcpy", !memcmp(d1, d2, 12)); free(src);
        memset(d1, 'A', 12); memset(d2, 'A', 12); src = H("");
        CHECK(ft_strlcpy(d1, src, sizes[i]) == ref_lcpy(d2, src, sizes[i])); CHECKF("ft_strlcpy", !memcmp(d1, d2, 12)); free(src);
    }
    /* strlcat: unterminated-within-size destinations, empty sources, SIZE_MAX */
    const char *srcs[] = {"AAAAAAAAA", "", "123", "A"};
    for (unsigned si = 0; si < 4; si++) for (unsigned pre = 0; pre <= 12; pre += 3) for (unsigned i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        char d1[40], d2[40]; memset(d1, 0, 40); memset(d2, 0, 40); memset(d1, 'B', pre); memset(d2, 'B', pre);
        char *src = H(srcs[si]);
        CHECK(ft_strlcat(d1, src, sizes[i]) == ref_lcat(d2, src, sizes[i])); CHECKF("ft_strlcat", !memcmp(d1, d2, 40)); free(src);
    }
    /* strchr / strrchr */
    { char s[] = "tripouille"; char e[] = "";
      CHECK(ft_strchr(s, 't') == s && ft_strchr(s, 'l') == s + 7 && !ft_strchr(s, 'z') && ft_strchr(s, 0) == s + 10 && ft_strchr(s, 't' + 256) == s);
      CHECK(ft_strrchr(s, 't') == s && ft_strrchr(s, 'l') == s + 8 && !ft_strrchr(s, 'z') && ft_strrchr(s, 0) == s + 10 && ft_strrchr(s, 't' + 256) == s);
      CHECK(ft_strrchr(e, 'V') == NULL && ft_strrchr(e, 0) == e); }
    /* memchr / memcmp */
    { char s[] = {0, 1, 2, 3, 4, 5};
      CHECK(ft_memchr(s, 0, 0) == NULL && ft_memchr(s, 0, 1) == s && ft_memchr(s, 2, 3) == s + 2 && ft_memchr(s, 6, 6) == NULL && ft_memchr(s, 2 + 256, 3) == s + 2); }
}

/* ======================= BEST-PRACTICE GROUPS ======================= */
static void g_big_size(void)
{
    if (sizeof(size_t) < 8) { SKIP("size_t is 32-bit on this platform"); return; }
    char d[16] = "x"; size_t r = ft_strlcpy(d, "hello", (size_t)1 << 32); CHECK(r == 5); CHECK(!strcmp(d, "hello"));
    char e[16] = "ab"; r = ft_strlcat(e, "cd", (size_t)1 << 32); CHECK(r == 4); CHECK(!strcmp(e, "abcd"));
    char f[16] = "x"; r = ft_strlcpy(f, "hello", ((size_t)1 << 32) + 3); CHECK(r == 5); CHECK(!strcmp(f, "hello"));
}

#define NT(label, ...) do { fflush(stdout); pid_t pid_ = fork(); \
    if (pid_ == 0) { int z_ = open("/dev/null", O_WRONLY); dup2(z_, 1); dup2(z_, 2); __VA_ARGS__; _exit(0); } \
    int st_ = 0; waitpid(pid_, &st_, 0); \
    if (WIFEXITED(st_) && WEXITSTATUS(st_) == 0) pass++; else { fail++; printf("NULL-unsafe: %s\n", label); } } while (0)

static void g_null_inputs(void)
{
    int dn = open("/dev/null", O_WRONLY); char b[] = "abc"; t_list *n = ft_lstnew(NULL);
    NT("ft_substr(NULL, ...)",        ft_substr(NULL, 0, 1));
    NT("ft_strjoin(NULL, s)",         ft_strjoin(NULL, "a"));
    NT("ft_strjoin(s, NULL)",         ft_strjoin("a", NULL));
    NT("ft_strtrim(NULL, set)",       ft_strtrim(NULL, "a"));
    NT("ft_strtrim(s, NULL)",         ft_strtrim("a", NULL));
    NT("ft_split(NULL, c)",           ft_split(NULL, ' '));
    NT("ft_strmapi(NULL, f)",         ft_strmapi(NULL, mp));
    NT("ft_strmapi(s, NULL)",         ft_strmapi("abc", NULL));
    NT("ft_striteri(NULL, f)",        ft_striteri(NULL, up));
    NT("ft_striteri(s, NULL)",        ft_striteri(b, NULL));
    NT("ft_putstr_fd(NULL, fd)",      ft_putstr_fd(NULL, dn));
    NT("ft_putendl_fd(NULL, fd)",     ft_putendl_fd(NULL, dn));
    NT("ft_lstadd_back(NULL, node)",  ft_lstadd_back(NULL, n));
    NT("ft_lstadd_front(NULL, node)", ft_lstadd_front(NULL, n));
    NT("ft_lstdelone(NULL, del)",     ft_lstdelone(NULL, del));
    NT("ft_lstclear(NULL, del)",      ft_lstclear(NULL, del));
    NT("ft_lstiter(NULL, f)",         ft_lstiter(NULL, noop));
    NT("ft_lstiter(lst, NULL)",       ft_lstiter(n, NULL));
    NT("ft_lstmap(NULL, f, del) returns NULL",   { t_list *m = ft_lstmap(NULL, dupf, del); if (m) _exit(3); });
    NT("ft_lstmap(lst, NULL, del) returns NULL", { t_list *m = ft_lstmap(n, NULL, del); if (m) _exit(3); });
    close(dn); free(n);
}

#define FAILGROUP(fname, expr, freeexpr) \
static void fname(void) { int bad = 0, trig = 0; \
    if (!HAVE_TRACK) { SKIP("linker cannot wrap malloc here"); return; } \
    for (long k = 1; k <= 40; k++) { g_count = 0; g_fail_at = k; void *r = (void *)(expr); long used = g_count; g_fail_at = 0; \
        if (used >= k) { trig++; if (r) bad++; } if (r) { freeexpr; } } \
    CHECK(trig > 0); CHECK(bad == 0); }

FAILGROUP(g_fail_strdup,  ft_strdup("hello"), free(r))
FAILGROUP(g_fail_substr,  ft_substr("hello world", 2, 5), free(r))
FAILGROUP(g_fail_strjoin, ft_strjoin("foo", "bar"), free(r))
FAILGROUP(g_fail_strtrim, ft_strtrim("  hi there  ", " "), free(r))
FAILGROUP(g_fail_itoa,    ft_itoa(-12345), free(r))
FAILGROUP(g_fail_strmapi, ft_strmapi("abc", mp), free(r))
FAILGROUP(g_fail_calloc,  ft_calloc(5, 4), free(r))
FAILGROUP(g_fail_lstnew,  ft_lstnew(NULL), free(r))
FAILGROUP(g_fail_split,   ft_split("a bb ccc dddd eeeee ffffff", ' '), free_split(r))

static void g_fail_lstmap(void)
{
    int bad = 0, trig = 0;
    if (!HAVE_TRACK) { SKIP("linker cannot wrap malloc here"); return; }
    for (long k = 1; k <= 12; k++) {
        t_list *base = NULL; for (int i = 0; i < 5; i++) ft_lstadd_back(&base, ft_lstnew(dupstr("v")));
        g_count = 0; g_fail_at = k; t_list *r = ft_lstmap(base, dupf, del); long used = g_count; g_fail_at = 0;
        if (used >= k) { trig++; if (r) bad++; }
        ft_lstclear(&r, del); ft_lstclear(&base, del);
    }
    CHECK(trig > 0); CHECK(bad == 0);
}

static const struct { const char *name; void (*fn)(void); } groups[] = {
    {"ctype", g_ctype}, {"mem", g_mem}, {"str", g_str}, {"atoi", g_atoi}, {"itoa", g_itoa}, {"calloc", g_calloc},
    {"calloc_edges", g_calloc_edges}, {"substr_join_trim", g_substr_join_trim}, {"split", g_split}, {"mapi_iteri", g_mapi_iteri},
    {"put_fd", g_put_fd}, {"lists", g_lists}, {"alloc_sizes", g_alloc_sizes}, {"known_cases", g_known_cases},
    {"big_size", g_big_size}, {"null_inputs", g_null_inputs},
    {"fail_strdup", g_fail_strdup}, {"fail_substr", g_fail_substr}, {"fail_strjoin", g_fail_strjoin},
    {"fail_strtrim", g_fail_strtrim}, {"fail_itoa", g_fail_itoa}, {"fail_strmapi", g_fail_strmapi},
    {"fail_calloc", g_fail_calloc}, {"fail_lstnew", g_fail_lstnew}, {"fail_split", g_fail_split}, {"fail_lstmap", g_fail_lstmap},
};

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2) { for (unsigned i = 0; i < sizeof groups / sizeof *groups; i++) puts(groups[i].name); return 2; }
    const char *fz = getenv("LIBFT_FUZZ"); if (fz && atoi(fz) > 0) fuzz_pct = atoi(fz);
#if defined(HAVE_BT) && !defined(ASAN_BUILD)
    signal(SIGSEGV, crash_handler); signal(SIGABRT, crash_handler); signal(SIGBUS, crash_handler); signal(SIGFPE, crash_handler);
#endif
    for (unsigned i = 0; i < sizeof groups / sizeof *groups; i++)
        if (!strcmp(argv[1], groups[i].name)) {
            groups[i].fn();
            if (skipped) { printf("@@SKIP %s\n", skipmsg); return 0; }
            printf("@@RESULT %ld %ld\n", pass, fail);
            if (HAVE_TRACK) printf("@@MEM live=%ld badfree=%ld corrupt=%ld\n", g_live, g_badfree, g_corrupt);
#if defined(HAVE_BT) && !defined(NO_WRAP)
            if (g_live > 0) for (size_t k = 0; k < REG_CAP; k++)
                if (reg[k].p && reg[k].p != TOMB) { const char *nm = ft_name_of(reg[k].caller); if (nm) dprintf(1, "@@LEAKFN %s\n", nm); }
#endif
            return fail != 0;
        }
    fprintf(stderr, "unknown group %s\n", argv[1]);
    return 2;
}
