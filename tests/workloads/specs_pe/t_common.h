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

/* Does this mode ask the node at `level` to wait for its child?
 * level 0 = launcher, 1 = bootstrap. */
ORC_UNUSED static int tree_waits(const char *mode, int level) {
    if (strcmp(mode, "launcher-exits") == 0) return level != 0;
    if (strcmp(mode, "orphan-tree") == 0) return 0;
    if (strcmp(mode, "bootstrap-only") == 0) return 0;
    return 1;
}

#endif /* LEXE_TREE_COMMON_H */
