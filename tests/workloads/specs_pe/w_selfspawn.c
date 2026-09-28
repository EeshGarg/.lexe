/* A process that spawns ITSELF and redirects the child's standard handles.
 *
 * One binary, two roles, chosen by argv[1], which keeps the fixture self-contained:
 * there is no second executable to stage and no chance of the two halves drifting
 * apart. Real Windows software does this constantly -- a program re-invoking itself
 * elevated, as a service, or as a worker.
 *
 * The parent opens two files, hands them to the child as hStdOutput and hStdError
 * through STARTUPINFO with STARTF_USESTDHANDLES, and then reads them back after the
 * child is gone. That covers three things at once that nothing else in this corpus
 * does: handle INHERITANCE, a child whose streams are files rather than pipes, and
 * a child's output recovered by its parent after the child has exited.
 *
 * Each role writes its own oracle file, so both halves are on disk afterwards.
 */
#include "oracle_win.h"

static int self_path(wchar_t *out, size_t n) {
    DWORD len = GetModuleFileNameW(NULL, out, (DWORD)n);
    return len > 0 && len < n;
}

static int run_child(void) {
    orc_begin_fixed("w_selfspawn_child");
    orc_kv("ROLE", "child");
    /* These two lines go to the redirected handles, which are FILES the parent
     * opened, and the parent checks for them there. */
    fprintf(stdout, "CHILD_STDOUT_MARKER=yes\n");
    fflush(stdout);
    fprintf(stderr, "CHILD_STDERR_MARKER=yes\n");
    fflush(stderr);
    orc_kv("CHILD_WROTE_BOTH_STREAMS", "yes");
    orc_kv("CHILD_EXIT_INTENT", "7");
    orc_check("CHILD_COMPLETED", 1);
    orc_end();
    return 7;
}

static int contains(const wchar_t *name, const char *needle, unsigned long *bytes) {
    char buf[4096];
    DWORD got = 0;
    HANDLE h = CreateFileW(name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    *bytes = 0;
    if (h == INVALID_HANDLE_VALUE) return 0;
    ReadFile(h, buf, sizeof buf - 1, &got, NULL);
    buf[got] = 0;
    CloseHandle(h);
    *bytes = (unsigned long)got;
    return strstr(buf, needle) != NULL;
}

int main(int argc, char **argv) {
    const char *role = argc > 1 ? argv[1] : "parent";
    wchar_t self[MAX_PATH], cmd[MAX_PATH + 64];
    SECURITY_ATTRIBUTES sa;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    HANDLE out_file, err_file;
    DWORD code = 0xFFFFFFFFu;
    unsigned long out_bytes = 0, err_bytes = 0;

    if (strcmp(role, "child") == 0) return run_child();

    orc_begin_fixed("w_selfspawn_parent");
    orc_kv("ROLE", "parent");
    orc_check("SELF_PATH", self_path(self, MAX_PATH));

    ZeroMemory(&sa, sizeof sa);
    sa.nLength = sizeof sa;
    sa.bInheritHandle = TRUE;          /* the whole point: the child gets these */
    sa.lpSecurityDescriptor = NULL;
    out_file = CreateFileW(L"child_stdout.txt", GENERIC_WRITE, FILE_SHARE_READ, &sa,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    err_file = CreateFileW(L"child_stderr.txt", GENERIC_WRITE, FILE_SHARE_READ, &sa,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    orc_check("OPENED_CHILD_STDOUT_FILE", out_file != INVALID_HANDLE_VALUE);
    orc_check("OPENED_CHILD_STDERR_FILE", err_file != INVALID_HANDLE_VALUE);
    if (out_file == INVALID_HANDLE_VALUE || err_file == INVALID_HANDLE_VALUE)
        return orc_end();

    ZeroMemory(&si, sizeof si);
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = out_file;
    si.hStdError = err_file;
    ZeroMemory(&pi, sizeof pi);
    _snwprintf(cmd, MAX_PATH + 64, L"\"%s\" child", self);
    if (!CreateProcessW(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        orc_check("SPAWNED_SELF", 0);
        orc_werr_now("SPAWN_ERROR");
        return orc_end();
    }
    orc_check("SPAWNED_SELF", 1);
    orc_obs("CHILD_PID", "%lu", (unsigned long)pi.dwProcessId);
    CloseHandle(pi.hThread);
    orc_check("WAITED_FOR_CHILD",
              WaitForSingleObject(pi.hProcess, 60000) == WAIT_OBJECT_0);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    /* The parent must close its own copies before the content is guaranteed
     * flushed and readable, which is itself a real Windows gotcha. */
    CloseHandle(out_file);
    CloseHandle(err_file);

    orc_kv("CHILD_EXIT_DECIMAL", "%lu", (unsigned long)code);
    orc_check("CHILD_EXIT_WAS_SEVEN", code == 7);

    orc_check("CHILD_STDOUT_REACHED_THE_FILE",
              contains(L"child_stdout.txt", "CHILD_STDOUT_MARKER=yes", &out_bytes));
    orc_check("CHILD_STDERR_REACHED_THE_FILE",
              contains(L"child_stderr.txt", "CHILD_STDERR_MARKER=yes", &err_bytes));
    orc_obs("CHILD_STDOUT_FILE_BYTES", "%lu", out_bytes);
    orc_obs("CHILD_STDERR_FILE_BYTES", "%lu", err_bytes);
    /* The streams must not have been crossed: the stderr marker must NOT be in the
     * stdout file. That is the assertion a single combined redirect would fail. */
    {
        unsigned long junk = 0;
        orc_check("STREAMS_WERE_NOT_CROSSED",
                  !contains(L"child_stdout.txt", "CHILD_STDERR_MARKER", &junk)
                  && !contains(L"child_stderr.txt", "CHILD_STDOUT_MARKER", &junk));
    }
    orc_check("CHILD_LEFT_ITS_OWN_ORACLE",
              GetFileAttributesW(L"w_selfspawn_child.oracle") != INVALID_FILE_ATTRIBUTES);
    return orc_end();
}
