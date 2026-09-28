/* Job objects: the Windows way to own a whole process tree and kill it as one
 * thing. Steam, launchers and installers all use them, and they are the mechanism
 * that makes "the application and everything it started" a real, enforceable set
 * rather than a guess a supervisor has to make from parent pids.
 *
 * One binary, two roles by argv[1]. The parent:
 *   creates a job, spawns itself SUSPENDED, assigns the child to the job, resumes
 *   it, waits until the child reports it is alive, then calls TerminateJobObject
 *   with a chosen status and checks that the child died with exactly that status
 *   and did NOT reach its completion line.
 *
 * The suspended-then-assign order matters: assigning after the child has already
 * started would be a race, and a child that got to exit on its own would prove
 * nothing. The child's own oracle file, truncated at the point the job killed it, is
 * the evidence.
 */
#include "oracle_win.h"

#define JOB_KILL_STATUS 55

static int run_child(void) {
    int i;
    orc_begin_fixed("w_jobobject_child");
    orc_kv("ROLE", "child");
    orc_kv("CHILD_ALIVE", "yes");
    {
        FILE *f = fopen("job_child_alive.flag", "w");
        if (f) { fprintf(f, "alive\n"); fclose(f); }
    }
    /* Long enough that the parent certainly kills it first. */
    for (i = 0; i < 300; i++) Sleep(50);
    orc_kv("CHILD_WAS_NOT_KILLED", "yes");
    orc_check("CHILD_RAN_TO_COMPLETION", 1);
    orc_end();
    return 0;
}

int main(int argc, char **argv) {
    const char *role = argc > 1 ? argv[1] : "parent";
    wchar_t self[MAX_PATH], cmd[MAX_PATH + 64], jobname[128];
    HANDLE job;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    DWORD code = 0xFFFFFFFFu, len;
    int spins;

    if (strcmp(role, "child") == 0) return run_child();

    orc_begin_fixed("w_jobobject_parent");
    orc_kv("ROLE", "parent");
    len = GetModuleFileNameW(NULL, self, MAX_PATH);
    orc_check("SELF_PATH", len > 0 && len < MAX_PATH);
    if (!(len > 0 && len < MAX_PATH)) return orc_end();

    _snwprintf(jobname, 128, L"Local\\LexeWorkloadJob-%lu",
               (unsigned long)GetCurrentProcessId());
    SetLastError(0);
    job = CreateJobObjectW(NULL, jobname);
    orc_check("CREATE_JOB_OBJECT", job != NULL);
    if (!job) { orc_werr_now("CREATE_JOB_ERROR"); return orc_end(); }

    /* Opening the job by name must reach the same object. */
    {
        HANDLE again = OpenJobObjectW(JOB_OBJECT_ALL_ACCESS, FALSE, jobname);
        orc_check("OPEN_JOB_BY_NAME", again != NULL);
        if (again) CloseHandle(again);
    }

    ZeroMemory(&si, sizeof si);
    si.cb = sizeof si;
    ZeroMemory(&pi, sizeof pi);
    _snwprintf(cmd, MAX_PATH + 64, L"\"%s\" child", self);
    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED,
                        NULL, NULL, &si, &pi)) {
        orc_check("SPAWNED_SUSPENDED_CHILD", 0);
        orc_werr_now("SPAWN_ERROR");
        CloseHandle(job);
        return orc_end();
    }
    orc_check("SPAWNED_SUSPENDED_CHILD", 1);
    orc_obs("CHILD_PID", "%lu", (unsigned long)pi.dwProcessId);

    SetLastError(0);
    orc_check("ASSIGN_PROCESS_TO_JOB", AssignProcessToJobObject(job, pi.hProcess) != 0);
    orc_werr_now("ASSIGN_ERROR");
    {
        BOOL in_job = FALSE;
        if (IsProcessInJob(pi.hProcess, job, &in_job))
            orc_kv("CHILD_IS_IN_THE_JOB", "%s", in_job ? "yes" : "no");
        else
            orc_kv("CHILD_IS_IN_THE_JOB", "unknown");
    }
    orc_check("RESUMED_CHILD", ResumeThread(pi.hThread) != (DWORD)-1);
    CloseHandle(pi.hThread);

    for (spins = 0; spins < 400; spins++) {
        if (GetFileAttributesW(L"job_child_alive.flag") != INVALID_FILE_ATTRIBUTES) break;
        Sleep(25);
    }
    orc_check("CHILD_REPORTED_ALIVE_BEFORE_KILL",
              GetFileAttributesW(L"job_child_alive.flag") != INVALID_FILE_ATTRIBUTES);

    SetLastError(0);
    orc_check("TERMINATE_JOB_OBJECT", TerminateJobObject(job, JOB_KILL_STATUS) != 0);
    orc_werr_now("TERMINATE_JOB_ERROR");
    orc_check("CHILD_DIED_PROMPTLY",
              WaitForSingleObject(pi.hProcess, 30000) == WAIT_OBJECT_0);
    GetExitCodeProcess(pi.hProcess, &code);
    orc_kv("CHILD_EXIT_DECIMAL", "%lu", (unsigned long)code);
    orc_kv("CHILD_EXIT_HEX", "0x%08lx", (unsigned long)code);
    orc_check("JOB_STATUS_BECAME_THE_CHILD_EXIT_CODE", code == JOB_KILL_STATUS);
    CloseHandle(pi.hProcess);
    CloseHandle(job);

    /* The child's own oracle must exist and must STOP before its completion line:
     * that is the proof the job killed it rather than it finishing early. */
    {
        char buf[2048];
        DWORD got = 0;
        HANDLE f = CreateFileW(L"w_jobobject_child.oracle", GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        orc_check("CHILD_ORACLE_EXISTS", f != INVALID_HANDLE_VALUE);
        if (f != INVALID_HANDLE_VALUE) {
            ReadFile(f, buf, sizeof buf - 1, &got, NULL);
            buf[got] = 0;
            CloseHandle(f);
            orc_check("CHILD_GOT_AS_FAR_AS_ALIVE", strstr(buf, "CHILD_ALIVE=yes") != NULL);
            orc_check("CHILD_NEVER_COMPLETED",
                      strstr(buf, "CHILD_WAS_NOT_KILLED") == NULL);
            orc_check("CHILD_WROTE_NO_RESULT", strstr(buf, "RESULT=") == NULL);
        }
    }
    return orc_end();
}
