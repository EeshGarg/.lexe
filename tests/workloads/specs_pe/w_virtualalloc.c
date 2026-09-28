/* Virtual memory by hand: VirtualAlloc, VirtualQuery, VirtualProtect, VirtualFree.
 *
 * This is the allocator underneath every Windows heap, and the reserve/commit
 * distinction has no POSIX equivalent that is quite the same shape: a RESERVED
 * region has address space but no backing and no access, a COMMITTED one has both.
 * A layer that treats reserve and commit as the same thing passes every simple
 * allocation test and then falls over on a program that reserves a large region and
 * commits it a page at a time -- which is exactly what a game's streaming allocator
 * does.
 *
 * argv[1]:
 *   states    reserve, query, commit, query, protect, query, decommit, query,
 *             release -- every transition checked against what VirtualQuery says
 *   noaccess  commit a page, make it PAGE_NOACCESS, then touch it: the resulting
 *             access violation is caught by a top-level filter, which reports the
 *             code and exits 12. Memory protection that is not enforced is the
 *             failure this catches, and it would be invisible in `states`.
 */
#include "oracle_win.h"

#define REGION (64u * 1024u)

static const char *state_name(DWORD s) {
    switch (s) {
    case MEM_COMMIT:  return "MEM_COMMIT";
    case MEM_RESERVE: return "MEM_RESERVE";
    case MEM_FREE:    return "MEM_FREE";
    default:          return "other";
    }
}

static const char *protect_name(DWORD p) {
    switch (p) {
    case 0:                  return "none";
    case PAGE_NOACCESS:      return "PAGE_NOACCESS";
    case PAGE_READONLY:      return "PAGE_READONLY";
    case PAGE_READWRITE:     return "PAGE_READWRITE";
    case PAGE_WRITECOPY:     return "PAGE_WRITECOPY";
    case PAGE_EXECUTE:       return "PAGE_EXECUTE";
    case PAGE_EXECUTE_READ:  return "PAGE_EXECUTE_READ";
    case PAGE_EXECUTE_READWRITE: return "PAGE_EXECUTE_READWRITE";
    default:                 return "other";
    }
}

static void query(void *p, const char *label) {
    MEMORY_BASIC_INFORMATION mbi;
    char key[128];
    SIZE_T n;
    ZeroMemory(&mbi, sizeof mbi);
    n = VirtualQuery(p, &mbi, sizeof mbi);
    snprintf(key, sizeof key, "%s_QUERY", label);
    orc_kv(key, "%s", n == sizeof mbi ? "ok" : "short");
    snprintf(key, sizeof key, "%s_STATE", label);
    orc_kv(key, "%s", state_name(mbi.State));
    snprintf(key, sizeof key, "%s_PROTECT", label);
    orc_kv(key, "%s", protect_name(mbi.Protect));
    snprintf(key, sizeof key, "%s_REGION_SIZE", label);
    orc_kv(key, "%lu", (unsigned long)mbi.RegionSize);
}

static LONG WINAPI on_fault(EXCEPTION_POINTERS *ep) {
    orc_kv("FAULT_CODE", "0x%08lx", (unsigned long)ep->ExceptionRecord->ExceptionCode);
    orc_kv("FAULT_WAS_ACCESS_VIOLATION", "%s",
           ep->ExceptionRecord->ExceptionCode == (DWORD)EXCEPTION_ACCESS_VIOLATION
           ? "yes" : "no");
    if (ep->ExceptionRecord->NumberParameters >= 1)
        orc_kv("FAULT_WAS_A_WRITE", "%s",
               ep->ExceptionRecord->ExceptionInformation[0] == 1 ? "yes" : "no");
    orc_kv("PROTECTION_WAS_ENFORCED", "yes");
    orc_check("NOACCESS_PAGE_REALLY_FAULTED", 1);
    orc_end();
    ExitProcess(12);
    return EXCEPTION_EXECUTE_HANDLER;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "states";
    SYSTEM_INFO si;
    void *p;
    DWORD old = 0;
    orc_begin("pe-mem-virtual");
    orc_kv("VIRTUAL_MODE", "%s", mode);
    GetSystemInfo(&si);
    orc_obs("PAGE_SIZE", "%lu", (unsigned long)si.dwPageSize);
    orc_obs("ALLOCATION_GRANULARITY", "%lu", (unsigned long)si.dwAllocationGranularity);

    if (strcmp(mode, "noaccess") == 0) {
        p = VirtualAlloc(NULL, REGION, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        orc_check("COMMIT", p != NULL);
        if (!p) { orc_werr_now("COMMIT_ERROR"); return orc_end(); }
        *(volatile unsigned char *)p = 0x5A;
        orc_check("WRITABLE_WHILE_READWRITE", *(volatile unsigned char *)p == 0x5A);
        orc_check("PROTECT_NOACCESS",
                  VirtualProtect(p, si.dwPageSize, PAGE_NOACCESS, &old) != 0);
        orc_kv("PREVIOUS_PROTECTION", "%s", protect_name(old));
        query(p, "AFTER_NOACCESS");
        SetUnhandledExceptionFilter(on_fault);
        orc_kv("DELIBERATE_FAULT", "write-to-PAGE_NOACCESS");
        orc_kv("WORK_BEFORE_FAULT", "done");
        *(volatile unsigned char *)p = 0x5B;
        orc_kv("FAULT_DID_NOT_HAPPEN", "yes");
        orc_check("PROTECTION_WAS_ENFORCED_CHECK", 0);
        return orc_end();
    }

    p = VirtualAlloc(NULL, REGION, MEM_RESERVE, PAGE_NOACCESS);
    orc_check("RESERVE", p != NULL);
    if (!p) { orc_werr_now("RESERVE_ERROR"); return orc_end(); }
    query(p, "AFTER_RESERVE");

    orc_check("COMMIT", VirtualAlloc(p, si.dwPageSize, MEM_COMMIT, PAGE_READWRITE) != NULL);
    query(p, "AFTER_COMMIT");
    *(volatile unsigned char *)p = 0x5A;
    orc_check("COMMITTED_PAGE_IS_WRITABLE", *(volatile unsigned char *)p == 0x5A);
    /* The rest of the region is still only reserved, and must still say so. */
    query((unsigned char *)p + si.dwPageSize, "REST_OF_REGION");

    orc_check("PROTECT_READONLY",
              VirtualProtect(p, si.dwPageSize, PAGE_READONLY, &old) != 0);
    orc_kv("PROTECT_PREVIOUS", "%s", protect_name(old));
    orc_check("PREVIOUS_WAS_READWRITE", old == PAGE_READWRITE);
    query(p, "AFTER_PROTECT");
    orc_check("READONLY_PAGE_STILL_READABLE", *(volatile unsigned char *)p == 0x5A);

    orc_check("DECOMMIT", VirtualFree(p, si.dwPageSize, MEM_DECOMMIT) != 0);
    query(p, "AFTER_DECOMMIT");
    orc_check("RELEASE", VirtualFree(p, 0, MEM_RELEASE) != 0);
    query(p, "AFTER_RELEASE");

    /* MEM_RELEASE with a non-zero size is an error, and a distinct one. */
    {
        void *q = VirtualAlloc(NULL, REGION, MEM_RESERVE, PAGE_NOACCESS);
        if (q) {
            SetLastError(0);
            orc_kv("RELEASE_WITH_SIZE", "%s",
                   VirtualFree(q, REGION, MEM_RELEASE) ? "accepted" : "refused");
            orc_werr_now("RELEASE_WITH_SIZE_ERROR");
            VirtualFree(q, 0, MEM_RELEASE);
        }
    }
    return orc_end();
}
