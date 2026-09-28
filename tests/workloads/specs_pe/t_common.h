/* t_common.h -- shared machinery for the process-tree family.
 *
 * The tree is a deliberate shape, not scattered specimens:
 *
 *   t_launcher.exe -> t_bootstrap.exe -> t_main.exe -> t_helper.exe
 *                                                      t_worker.exe
 *                                                      t_crash_handler.exe
 *
 * A single mode token is passed down the whole chain and each node decides what
 * to do with it, so one set of six binaries produces every shape worth testing:
 * a launcher that waits, a launcher that exits immediately, each parent exiting
 * as soon as its child is started, a fan-out to three children, a helper that
 * outlives everything above it, and an abnormally terminating child.
 *
 * Every node writes its OWN oracle file, named after the node rather than after
 * the fixture, so the whole tree is reconstructible from the run directory after
 * the fact. That matters here more than anywhere else in the corpus: when the
 * launcher exits immediately there is nothing left to report to, and stdout is
 * not a channel that survives Proton anyway.
 *
 * Children are located RELATIVE TO THE PARENT'S OWN IMAGE (GetModuleFileNameW),
 * which is how real Windows launchers find their payload, and is independent of
 * the working directory.
 */
#ifndef LEXE_TREE_COMMON_H
#define LEXE_TREE_COMMON_H

#include "oracle_win.h"

/* Absolute path to a sibling executable of the running image. */
ORC_UNUSED static int tree_sibling(const wchar_t *name, wchar_t *out, size_t n) {
    wchar_t self[MAX_PATH];
    DWORD len = GetModuleFileNameW(NULL, self, MAX_PATH);
    size_t i, cut = 0;
    if (len == 0) return 0;
    for (i = 0; i < len; i++) if (self[i] == L'\\' || self[i] == L'/') cut = i;
    self[cut] = 0;
    _snwprintf(out, n, L"%s\\%s", self, name);
    return 1;
}

/* Start a sibling, passing the mode token on. Returns the process handle, or
 * NULL, and always reports what happened. `detached` uses DETACHED_PROCESS plus
 * CREATE_NEW_PROCESS_GROUP, which is how a process is deliberately cut loose
 * from its parent's console and process group. */
ORC_UNUSED static HANDLE tree_spawn(const wchar_t *exe_name, const char *mode,
                                    int detached, const char *label) {
    wchar_t path[MAX_PATH], cmd[MAX_PATH + 128], wmode[64];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    char key[128];
    DWORD flags = detached ? (DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP) : 0;
    if (!tree_sibling(exe_name, path, MAX_PATH)) {
        snprintf(key, sizeof key, "%s_SPAWN", label);
        orc_kv(key, "no-module-path");
        return NULL;
    }
    MultiByteToWideChar(CP_UTF8, 0, mode, -1, wmode, 64);
    _snwprintf(cmd, MAX_PATH + 128, L"\"%s\" %s", path, wmode);
    ZeroMemory(&si, sizeof si);
    si.cb = sizeof si;
    ZeroMemory(&pi, sizeof pi);
    if (!CreateProcessW(NULL, cmd, NULL, NULL, detached ? FALSE : TRUE, flags,
                        NULL, NULL, &si, &pi)) {
        snprintf(key, sizeof key, "%s_SPAWN", label);
        orc_kv(key, "fail");
        snprintf(key, sizeof key, "%s_SPAWN_ERROR", label);
        orc_werr(key, GetLastError());
        return NULL;
    }
    snprintf(key, sizeof key, "%s_SPAWN", label);
    orc_kv(key, "ok");
    snprintf(key, sizeof key, "%s_PID", label);
    orc_obs(key, "%lu", (unsigned long)pi.dwProcessId);
    CloseHandle(pi.hThread);
    return pi.hProcess;
}

/* Wait for a child and report its exit status. The exit code is reported both as
 * a decimal and as hex, because an abnormal Windows status (0xC0000005 and
 * friends) is unreadable in decimal and is exactly what this family is about. */
ORC_UNUSED static DWORD tree_wait(HANDLE h, const char *label, DWORD timeout_ms) {
    char key[128];
    DWORD code = 0xFFFFFFFFu;
    DWORD w = WaitForSingleObject(h, timeout_ms);
    snprintf(key, sizeof key, "%s_WAIT", label);
    orc_kv(key, "%s", w == WAIT_OBJECT_0 ? "signalled" :
                      w == WAIT_TIMEOUT ? "timeout" : "failed");
    if (w == WAIT_OBJECT_0 && GetExitCodeProcess(h, &code)) {
        snprintf(key, sizeof key, "%s_EXIT_DECIMAL", label);
        orc_kv(key, "%lu", (unsigned long)code);
        snprintf(key, sizeof key, "%s_EXIT_HEX", label);
        orc_kv(key, "0x%08lx", (unsigned long)code);
        snprintf(key, sizeof key, "%s_EXIT_IS_ABNORMAL", label);
        orc_kv(key, "%s", (code & 0xC0000000u) == 0xC0000000u ? "yes" : "no");
    }
    CloseHandle(h);
    return code;
}

/* Like tree_spawn, but with an arbitrary argument STRING rather than just the mode
 * token, for the nodes that need a second argument (a hold time, a sleep). */
ORC_UNUSED static HANDLE tree_spawn_args(const wchar_t *exe_name, const char *args,
                                         int detached, const char *label) {
    wchar_t path[MAX_PATH], cmd[MAX_PATH + 256], wargs[192];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    char key[128];
    DWORD flags = detached ? (DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP) : 0;
    if (!tree_sibling(exe_name, path, MAX_PATH)) {
        snprintf(key, sizeof key, "%s_SPAWN", label);
        orc_kv(key, "no-module-path");
        return NULL;
    }
    MultiByteToWideChar(CP_UTF8, 0, args, -1, wargs, 192);
    _snwprintf(cmd, MAX_PATH + 256, L"\"%s\" %s", path, wargs);
    ZeroMemory(&si, sizeof si);
    si.cb = sizeof si;
    ZeroMemory(&pi, sizeof pi);
    if (!CreateProcessW(NULL, cmd, NULL, NULL, detached ? FALSE : TRUE, flags,
                        NULL, NULL, &si, &pi)) {
        snprintf(key, sizeof key, "%s_SPAWN", label);
        orc_kv(key, "fail");
        snprintf(key, sizeof key, "%s_SPAWN_ERROR", label);
        orc_werr(key, GetLastError());
        return NULL;
    }
    snprintf(key, sizeof key, "%s_SPAWN", label);
    orc_kv(key, "ok");
    snprintf(key, sizeof key, "%s_PID", label);
    orc_obs(key, "%lu", (unsigned long)pi.dwProcessId);
    CloseHandle(pi.hThread);
    return pi.hProcess;
}

/* Like tree_spawn, but the parent decides where the child's standard output and
 * standard error GO, by handing it handles through STARTUPINFO. Either handle may
 * be NULL, meaning "let the child inherit mine" -- which is how a child ends up
 * with one stream redirected and the other not, the shape this family needs in
 * order to tell the two streams apart at all.
 *
 * Handle inheritance is the whole mechanism here: the files must be opened with an
 * inheritable SECURITY_ATTRIBUTES and CreateProcessW must be called with
 * bInheritHandles TRUE, or the child gets nothing and writes into the void. */
ORC_UNUSED static HANDLE tree_spawn_redirected(const wchar_t *exe_name, const char *mode,
                                               HANDLE out, HANDLE err, const char *label) {
    wchar_t path[MAX_PATH], cmd[MAX_PATH + 128], wmode[64];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    char key[128];
    if (!tree_sibling(exe_name, path, MAX_PATH)) {
        snprintf(key, sizeof key, "%s_SPAWN", label);
        orc_kv(key, "no-module-path");
        return NULL;
    }
    MultiByteToWideChar(CP_UTF8, 0, mode, -1, wmode, 64);
    _snwprintf(cmd, MAX_PATH + 128, L"\"%s\" %s", path, wmode);
    ZeroMemory(&si, sizeof si);
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = out ? out : GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = err ? err : GetStdHandle(STD_ERROR_HANDLE);
    ZeroMemory(&pi, sizeof pi);
    if (!CreateProcessW(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        snprintf(key, sizeof key, "%s_SPAWN", label);
        orc_kv(key, "fail");
        snprintf(key, sizeof key, "%s_SPAWN_ERROR", label);
        orc_werr(key, GetLastError());
        return NULL;
    }
    snprintf(key, sizeof key, "%s_SPAWN", label);
    orc_kv(key, "ok");
    snprintf(key, sizeof key, "%s_PID", label);
    orc_obs(key, "%lu", (unsigned long)pi.dwProcessId);
    CloseHandle(pi.hThread);
    return pi.hProcess;
}

/* A file a parent opens for its child to write into. Inheritable on purpose. */
ORC_UNUSED static HANDLE tree_inheritable_file(const wchar_t *name) {
    SECURITY_ATTRIBUTES sa;
    ZeroMemory(&sa, sizeof sa);
    sa.nLength = sizeof sa;
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;
    return CreateFileW(name, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                       CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}

/* Read a whole small file, for a parent checking what its child wrote. */
ORC_UNUSED static int tree_file_contains(const wchar_t *name, const char *needle) {
    char buf[8192];
    DWORD got = 0;
    HANDLE h = CreateFileW(name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    ReadFile(h, buf, sizeof buf - 1, &got, NULL);
    buf[got] = 0;
    CloseHandle(h);
    return strstr(buf, needle) != NULL;
}

/* A flag file: the only way one process in this tree can prove to another that it
 * got somewhere, once the handles and the parent links are all gone. */
ORC_UNUSED static void tree_flag(const wchar_t *name) {
    HANDLE h = CreateFileW(name, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD written = 0;
    if (h != INVALID_HANDLE_VALUE) {
        WriteFile(h, "flag\n", 5, &written, NULL);
        CloseHandle(h);
    }
}

ORC_UNUSED static int tree_flag_present(const wchar_t *name) {
    return GetFileAttributesW(name) != INVALID_FILE_ATTRIBUTES;
}

/* PERSISTENT STATE owned by the tree rather than by any one process in it: every
 * node appends its own line to tree_state.dat, so after every process is gone the
 * file says which nodes ever existed. Append-and-close per line, because several
 * nodes may be alive at once and the file has to survive all of them. The ORDER of
 * the lines is not a contract and is never asserted -- only their presence is. */
ORC_UNUSED static void tree_state_note(const char *node) {
    FILE *f = fopen("tree_state.dat", "a");
    if (!f) return;
    fprintf(f, "STATE_%s=yes\n", node);
    fflush(f);
    fclose(f);
}

/* Does this mode ask the node at `level` to wait for its child?
 * level 0 = launcher, 1 = bootstrap, 2 = stage2. */
ORC_UNUSED static int tree_waits(const char *mode, int level) {
    if (strcmp(mode, "launcher-exits") == 0) return level != 0;
    if (strcmp(mode, "orphan-tree") == 0) return 0;
    if (strcmp(mode, "bootstrap-only") == 0) return 0;
    if (strcmp(mode, "deep-orphan") == 0) return 0;
    return 1;
}

/* The deep modes put an extra stage between the bootstrap and the application, so
 * the chain is six levels rather than three:
 *     launcher -> bootstrap -> stage2 -> main -> worker -> grandchild   */
ORC_UNUSED static int tree_is_deep(const char *mode) {
    return strncmp(mode, "deep-", 5) == 0;
}

#endif /* LEXE_TREE_COMMON_H */
