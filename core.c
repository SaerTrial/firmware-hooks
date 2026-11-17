/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Shared hook machinery: registry, configuration, dispatch and guest memory. */
#include "qemu/osdep.h"
#include <glib/gstdio.h>
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "qapi/qmp/qlist.h"
#include "qapi/qmp/qnum.h"
#include "qapi/qmp/qstring.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "exec/cpu_ldst.h"
#include "hooks/hook_engine.h"

#define AMBIGUOUS UINTPTR_MAX   /* symbol listed twice with different addresses */
#define NO_INPUT UINT64_MAX     /* copy_to_guest: plain values, not input bytes */

typedef struct Patch {
    char *hook;
    hook_fn fn;
    bool has_ret;               /* "ret" given: set this return value after the hook */
    uint64_t ret;
} Patch;

static GHashTable *hooks;       /* hook name -> hook_fn */
static GHashTable *symbols;     /* symbol name -> address */
static GHashTable *patches;     /* block-entry PC -> Patch */

#define BOOT_MAX_BLOCKS 10000000    /* with boot.input: give up on a boot that hangs */

/* The "boot" section. `active` from startup until the target is first reached. */
static struct {
    bool active;
    vaddr target;
    GHashTable *required;       /* block-entry PC -> seen yet? */
    GHashTable *avoid;          /* block-entry PCs of a failed boot */
    char *input;                /* boot.input path, or NULL: only judge each run's boot */
    uint64_t blocks, reads;     /* counted while booting from boot.input */
} boot;

void hook_register(const char *name, hook_fn fn)
{
    if (!hooks) {
        hooks = g_hash_table_new(g_str_hash, g_str_equal);
    }
    g_assert(!g_hash_table_contains(hooks, name));
    g_hash_table_insert(hooks, (gpointer)name, fn);
}

/* True if a -d option is on. QEMU's log trace backend always sets LOG_TRACE. */
static bool logging(void)
{
    return qemu_loglevel_mask(~LOG_TRACE);
}

/* Both log calls run on every hook call, so they format nothing without -d. */
void hook_log(const char *fmt, ...)
{
    g_autofree char *msg = NULL;
    va_list ap;

    if (!logging()) {
        return;
    }
    va_start(ap, fmt);
    msg = g_strdup_vprintf(fmt, ap);
    va_end(ap);
    hook_port_log(msg);
}

/* "input[k]" for one byte, "input[k..k+len-1]" for more: the names the
 * concolic executor gives these bytes. Then who took them. Bytes taken from
 * boot.input are "boot[k]": they are not part of the fuzz input. */
void hook_log_input(uint64_t offset, size_t len, const char *fmt, ...)
{
    const char *tape = hook_booting() ? "boot" : "input";
    g_autofree char *name = NULL, *reader = NULL;
    va_list ap;

    boot.reads += hook_booting();
    if (!logging()) {
        return;
    }
    name = len == 1 ? g_strdup_printf("%s[%" PRIu64 "]", tape, offset) :
        g_strdup_printf("%s[%" PRIu64 "..%" PRIu64 "]", tape, offset, offset + len - 1);
    va_start(ap, fmt);
    reader = g_strdup_vprintf(fmt, ap);
    va_end(ap);
    hook_log("%-20s %s\n", name, reader);
}

/* ---- Configuration ---- */

static G_NORETURN G_GNUC_PRINTF(1, 2) void config_error(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    error_vreport(fmt, ap);
    va_end(ap);
    exit(EXIT_FAILURE);
}

static uint64_t parse_num(const char *s, int base, const char *where)
{
    char *end;
    uint64_t v = g_ascii_strtoull(s, &end, base);   /* base 16 also takes "0x" */

    if (!*s || *end) {
        config_error("%s: \"%s\" is not a number", where, s);
    }
    return v;
}

/* A number written as a JSON number or as a string such as "0x08001234". */
static uint64_t config_num(QObject *obj, const char *where)
{
    QString *s = qobject_to(QString, obj);
    QNum *n = qobject_to(QNum, obj);
    int64_t v;

    if (s) {
        return parse_num(qstring_get_str(s), 0, where);
    }
    if (!n || !qnum_get_try_int(n, &v)) {
        config_error("%s: expected a number", where);
    }
    return v;
}

static void add_symbol(const char *name, uint64_t addr)
{
    gpointer old;

    if (g_hash_table_lookup_extended(symbols, name, NULL, &old) &&
        (uintptr_t)old != addr) {
        addr = AMBIGUOUS;       /* only an error if a patch uses this name */
    }
    g_hash_table_insert(symbols, g_strdup(name), (gpointer)(uintptr_t)addr);
}

/* One "address [type] name" per line, as nm prints it; '#' starts a comment. */
static void load_symbol_file(const char *path)
{
    g_autofree char *text = NULL;
    g_autoptr(GError) err = NULL;
    g_auto(GStrv) lines = NULL;

    if (!g_file_get_contents(path, &text, NULL, &err)) {
        config_error("symbols: %s", err->message);
    }
    lines = g_strsplit(text, "\n", -1);
    for (int i = 0; lines[i]; i++) {
        char addr[32], type[256], name[256], *hash = strchr(lines[i], '#');
        g_autofree char *where = g_strdup_printf("%s:%d", path, i + 1);
        int n;

        if (hash) {
            *hash = '\0';
        }
        n = sscanf(lines[i], "%31s %255s %255s", addr, type, name);
        if (n == 1) {
            config_error("%s: expected \"address [type] name\"", where);
        } else if (n >= 2) {
            add_symbol(n == 2 ? type : name, parse_num(addr, 16, where));
        }
    }
}

/* A file named in the configuration is looked up next to the configuration. */
static char *config_file(const char *config_path, const char *name)
{
    g_autofree char *dir = g_path_get_dirname(config_path);

    return g_path_is_absolute(name) ? g_strdup(name) : g_build_filename(dir, name, NULL);
}

/* "symbols": "file.syms" (next to the configuration) or {"name": "0x..."}. */
static void load_symbols(QObject *obj, const char *config_path)
{
    QString *file = qobject_to(QString, obj);
    QDict *inline_syms = qobject_to(QDict, obj);

    if (file) {
        g_autofree char *path = config_file(config_path, qstring_get_str(file));

        load_symbol_file(path);
    } else if (inline_syms) {
        for (const QDictEntry *e = qdict_first(inline_syms); e;
             e = qdict_next(inline_syms, e)) {
            add_symbol(e->key, config_num(e->value, e->key));
        }
    } else if (obj) {
        config_error("symbols: expected a file name or an object");
    }
}

/* Comma-separated registered hook names, for error messages. */
static char *hook_names(void)
{
    g_autoptr(GList) names = g_list_sort(g_hash_table_get_keys(hooks),
                                         (GCompareFunc)strcmp);
    GString *s = g_string_new(NULL);

    for (GList *l = names; l; l = l->next) {
        g_string_append_printf(s, "%s%s", s->len ? ", " : "", (char *)l->data);
    }
    return g_string_free(s, false);
}

/* Block-entry PC of a name from the symbol list. */
static vaddr symbol_pc(const char *sym, const char *where)
{
    gpointer v;

    if (!g_hash_table_lookup_extended(symbols, sym, NULL, &v)) {
        config_error("%s: symbol \"%s\" is not in the symbol list", where, sym);
    }
    if ((uintptr_t)v == AMBIGUOUS) {
        config_error("%s: symbol \"%s\" has more than one address", where, sym);
    }
    return hook_arch_entry((uintptr_t)v);
}

/* {"addr": "0x..." | "symbol": "name", "hook": "name", "ret": value?} */
static void add_patch(QDict *entry, int index)
{
    g_autofree char *where = g_strdup_printf("patch[%d]", index);
    const char *sym, *name;
    QObject *addr;
    Patch *p;
    vaddr pc;

    if (!entry) {
        config_error("%s: expected an object", where);
    }
    addr = qdict_get(entry, "addr");
    sym = qdict_get_try_str(entry, "symbol");
    name = qdict_get_try_str(entry, "hook") ?: qdict_get_try_str(entry, "name");

    if (!addr == !sym) {
        config_error("%s: give exactly one of \"addr\" and \"symbol\"", where);
    }
    pc = sym ? symbol_pc(sym, where) : hook_arch_entry(config_num(addr, where));

    p = g_new0(Patch, 1);
    p->fn = name && hooks ? g_hash_table_lookup(hooks, name) : NULL;
    if (!p->fn) {
        g_autofree char *known = hook_names();

        config_error("%s: unknown hook \"%s\"; registered hooks: %s",
                     where, name ?: "", known);
    }
    if (g_hash_table_contains(patches, (gpointer)(uintptr_t)pc)) {
        config_error("%s: 0x%" VADDR_PRIx " is already patched", where, pc);
    }
    p->hook = g_strdup(name);
    p->has_ret = qdict_haskey(entry, "ret");
    p->ret = p->has_ret ? config_num(qdict_get(entry, "ret"), where) : 0;
    g_hash_table_insert(patches, (gpointer)(uintptr_t)pc, p);
    hook_log("patch 0x%" VADDR_PRIx " -> %s\n", pc, p->hook);
}

/* An address in the boot section: a number, "0x0800043a", or a listed symbol. */
static vaddr boot_pc(QObject *obj, const char *where)
{
    QString *s = qobject_to(QString, obj);

    if (s && !g_ascii_isdigit(qstring_get_str(s)[0])) {
        return symbol_pc(qstring_get_str(s), where);
    }
    return hook_arch_entry(config_num(obj, where));
}

/* A list of addresses, as a table keyed by block-entry PC (all values NULL). */
static GHashTable *boot_pcs(QObject *obj, const char *where)
{
    GHashTable *pcs = g_hash_table_new(NULL, NULL);
    QList *list = qobject_to(QList, obj);
    QListEntry *e;
    int i = 0;

    if (obj && !list) {
        config_error("%s: expected a list", where);
    }
    if (list) {
        QLIST_FOREACH_ENTRY(list, e) {
            g_autofree char *item = g_strdup_printf("%s[%d]", where, i++);
            vaddr pc = boot_pc(qlist_entry_obj(e), item);

            g_hash_table_insert(pcs, (gpointer)(uintptr_t)pc, NULL);
        }
    }
    return pcs;
}

/* "boot": {"target": addr, "required": [addr]?, "avoid": [addr]?, "input": "file"?} */
static void load_boot(QObject *obj, const char *config_path)
{
    static const char *const keys[] = {"target", "required", "avoid", "input", NULL};
    QDict *conf = qobject_to(QDict, obj);
    GStatBuf st;

    if (!obj) {
        return;
    }
    if (!conf) {
        config_error("boot: expected an object");
    }
    for (const QDictEntry *e = qdict_first(conf); e; e = qdict_next(conf, e)) {
        if (!g_strv_contains(keys, e->key)) {
            config_error("boot: unknown key \"%s\"", e->key);
        }
    }
    if (!qdict_haskey(conf, "target")) {
        config_error("boot: \"target\" is missing");
    }
    boot.target = boot_pc(qdict_get(conf, "target"), "boot.target");
    boot.required = boot_pcs(qdict_get(conf, "required"), "boot.required");
    boot.avoid = boot_pcs(qdict_get(conf, "avoid"), "boot.avoid");
    if (g_hash_table_contains(boot.avoid, (gpointer)(uintptr_t)boot.target)) {
        config_error("boot: the target 0x%08" VADDR_PRIx " is also in \"avoid\"",
                     boot.target);
    }
    if (qdict_haskey(conf, "input")) {
        const char *name = qdict_get_try_str(conf, "input");

        if (!name) {
            config_error("boot.input: expected a file name");
        }
        boot.input = config_file(config_path, name);
        if (g_stat(boot.input, &st) || !st.st_size) {
            config_error("boot: cannot read %s, or it is empty", boot.input);
        }
    }
    boot.active = true;
}

void hook_load_config(QDict *conf, const char *config_path)
{
    QObject *obj = qdict_get(conf, "patch");
    QList *list = qobject_to(QList, obj);
    QListEntry *e;
    int i = 0;

    if (qdict_haskey(conf, "symbolize_at_pc")) {
        config_error("symbolize_at_pc was removed: hook the function that "
                     "receives the input instead (docs/hook-api.md)");
    }
    symbols = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    patches = g_hash_table_new(NULL, NULL);
    load_symbols(qdict_get(conf, "symbols"), config_path);
    load_boot(qdict_get(conf, "boot"), config_path);
    if (obj && !list) {
        config_error("patch: expected a list");
    }
    if (list) {
        QLIST_FOREACH_ENTRY(list, e) {
            add_patch(qobject_to(QDict, qlist_entry_obj(e)), i++);
        }
    }
}

/* ---- Boot ---- */

bool hook_booting(void)
{
    return boot.active && boot.input;
}

const char *hook_boot_input(void)
{
    return boot.input;
}

void hook_boot_fail(const char *fmt, ...)
{
    g_autofree char *file = g_path_get_basename(boot.input);
    g_autofree char *msg = NULL;
    va_list ap;

    va_start(ap, fmt);
    msg = g_strdup_vprintf(fmt, ap);
    va_end(ap);
    error_report("boot: %s %s", file, msg);
    exit(EXIT_FAILURE);
}

/* Is a required address still unseen? Reports the first one found. */
static bool boot_missed(vaddr *pc)
{
    GHashTableIter it;
    gpointer key, seen;

    g_hash_table_iter_init(&it, boot.required);
    while (g_hash_table_iter_next(&it, &key, &seen)) {
        if (!seen) {
            *pc = (uintptr_t)key;
            return true;
        }
    }
    return false;
}

/*
 * Judge the boot, one block at a time. Without boot.input a bad boot is just
 * a bad run: it is logged, and an avoid address ends it. With boot.input a
 * bad boot means the file does not fit, which stops the engine.
 */
HookBoot hook_boot_block(vaddr pc, uint64_t offset)
{
    gpointer key = (gpointer)(uintptr_t)pc;
    vaddr missed;

    if (!boot.active) {
        return HOOK_BOOT_GO;
    }
    if (g_hash_table_contains(boot.avoid, key)) {
        if (boot.input) {
            hook_boot_fail("reached avoid address 0x%08" VADDR_PRIx, pc);
        }
        hook_log("failed boot at input[%" PRIu64 "]: avoid address 0x%08" VADDR_PRIx
                 " reached\n", offset, pc);
        return HOOK_BOOT_FAILED;
    }
    if (g_hash_table_contains(boot.required, key)) {
        g_hash_table_replace(boot.required, key, GINT_TO_POINTER(1));   /* seen */
    }
    if (pc != boot.target) {
        if (boot.input && ++boot.blocks > BOOT_MAX_BLOCKS) {
            hook_boot_fail("did not reach the boot target 0x%08" VADDR_PRIx " after %d "
                           "blocks; is that address the start of a block?",
                           boot.target, BOOT_MAX_BLOCKS);
        }
        return HOOK_BOOT_GO;
    }

    if (boot_missed(&missed)) {
        if (boot.input) {
            hook_boot_fail("reached the boot target without required address 0x%08"
                           VADDR_PRIx, missed);
        }
        hook_log("passed boot at input[%" PRIu64 "]: required address 0x%08" VADDR_PRIx
                 " not reached\n", offset, missed);
    } else if (!boot.input) {
        hook_log("passed boot at input[%" PRIu64 "]: all required addresses reached\n",
                 offset);
    } else {
        g_autofree char *file = g_path_get_basename(boot.input);

        hook_log("boot: %s passed boot (target 0x%08" VADDR_PRIx ") after %" PRIu64
                 " reads, %" PRIu64 " bytes used\n", file, pc, boot.reads, offset);
    }
    boot.active = false;
    return boot.input ? HOOK_BOOT_SWITCH : HOOK_BOOT_GO;
}

/* ---- Dispatch ---- */

static const char *running_hook;    /* hooks run only from here; input logs name it */

bool hook_dispatch(CPUState *cs, vaddr pc)
{
    static unsigned calls;      /* numbers hook calls: [uart_recv_3] */
    Patch *p = patches ? g_hash_table_lookup(patches, (gpointer)(uintptr_t)pc) : NULL;

    if (!p) {
        return false;
    }
    printf("[%s_%u]\n", p->hook, calls);
    fflush(stdout);             /* input exhaustion leaves through _exit() */
    hook_log("[%s_%u]\n", p->hook, calls++);
    running_hook = p->hook;
    p->fn(cs);
    if (p->has_ret) {
        hook_set_ret(cs, p->ret);
    }
    hook_arch_return(cs);
    return true;
}

/* ---- Guest memory ---- */

/* Bytes from addr to the end of its guest page. Neighbouring guest pages are not necessarily
the neighbours in host memory, so some host copies may not cross a page. */
static size_t page_chunk(vaddr addr, size_t len)
{
    return MIN(len, -(addr | TARGET_PAGE_MASK));
}

/* Host address of `n` writable guest RAM bytes (within one page). The probe
 * never raises a guest fault: hooks run before the block's first instruction,
 * where a fault could not be unwound. It also drops translated code there. */
static void *guest_ram(CPUState *cs, vaddr addr, size_t n)
{
    void *host = NULL;
    int flags = probe_access_flags(cpu_env(cs), addr, n, MMU_DATA_STORE,
                                   cpu_mmu_index(cs, false), true, &host, 0);

    if ((flags & TLB_INVALID_MASK) || !host) {
        error_report("hook: guest 0x%" VADDR_PRIx " is not writable RAM", addr);
        abort();
    }
    return host;
}

/* Copy page by page. `offset` names the input bytes, or is NO_INPUT. */
static void copy_to_guest(CPUState *cs, vaddr addr, const uint8_t *buf,
                          size_t len, uint64_t offset)
{
    for (size_t done = 0, n; done < len; done += n) {
        void *host;

        n = page_chunk(addr + done, len - done);
        host = guest_ram(cs, addr + done, n);
        memcpy(host, buf + done, n);            /* concrete bytes first, */
        if (offset == NO_INPUT) {               /* then their symbolic state */
            hook_port_mem_concrete(host, n);
        } else {
            hook_port_mem_input(host, n, offset + done);
        }
    }
}

void hook_read_mem(CPUState *cs, vaddr addr, void *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        ((uint8_t *)buf)[i] = cpu_ldub_data(cpu_env(cs), addr + i);
    }
}

void hook_write_mem(CPUState *cs, vaddr addr, const void *buf, size_t len)
{
    copy_to_guest(cs, addr, buf, len, NO_INPUT);
}

void hook_input_to_guest(CPUState *cs, vaddr addr, size_t len)
{
    g_autofree uint8_t *buf = NULL;
    uint64_t offset;

    if (!len) {
        return;                 /* both engines end the run on a 0-byte read */
    }
    g_assert(len <= UINT32_MAX);
    for (size_t done = 0, n; done < len; done += n) {   /* a bad buffer fails */
        n = page_chunk(addr + done, len - done);        /* before any input is */
        guest_ram(cs, addr + done, n);                  /* taken from the tape */
    }
    buf = g_malloc(len);
    offset = hook_port_take_input(buf, len);
    hook_log_input(offset, len, "hook %s -> 0x%08" VADDR_PRIx, running_hook, addr);
    /* Bytes from boot.input are plain values: only the fuzz input is named. */
    copy_to_guest(cs, addr, buf, len, hook_booting() ? NO_INPUT : offset);
}
