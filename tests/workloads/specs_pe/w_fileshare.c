/* Windows file SHARING semantics, which have no POSIX equivalent to fall back on:
 * on Windows the sharing mode is declared at open time and the KERNEL refuses a
 * conflicting second open. On Unix nothing of the sort happens by default, so a
 * translation layer has to provide this itself, and an application that relies on
 * it -- a game holding its save file, an installer holding its log -- depends on it
 * being real.
 *
 *   share 0                 -> a second open for read must fail, SHARING VIOLATION
 *   share FILE_SHARE_READ   -> a second open for READ succeeds, PROVIDED the reader
 *                              itself permits the writer that is already there
 *                           -> a second open for WRITE still fails
 *   after the first handle closes -> everything opens again
 *
 * That proviso is the part this specimen originally got wrong, and it is worth
 * spelling out because it is the whole of how Windows sharing works: the check is
 * SYMMETRIC. The new opener's dwShareMode has to permit the access the EXISTING
 * handles already hold, at the same time as the existing handles' share modes have
 * to permit the new opener's access. A reader that asks for FILE_SHARE_READ alone
 * while a writer holds the file is saying "nobody may write this", and the writer
 * is already writing it -- so the open is refused, correctly. Both directions are
 * checked below.
 *
 * It also checks the case that surprises people: DeleteFileW while a handle is
 * open with no FILE_SHARE_DELETE must fail, which is why Windows installers
 * reboot and Unix ones do not.
 */
#include "oracle_win.h"

static const wchar_t *NAME = L"shared.dat";

static int try_open(DWORD access, DWORD share) {
    HANDLE h = CreateFileW(NAME, access, share, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    CloseHandle(h);
    return 1;
}

int main(void) {
    HANDLE first;
    DWORD written = 0;
    orc_begin("pe-fs-sharing-mode");

    first = CreateFileW(NAME, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL, NULL);
    orc_check("CREATE_EXCLUSIVE", first != INVALID_HANDLE_VALUE);
    if (first == INVALID_HANDLE_VALUE) { orc_werr_now("CREATE_ERROR"); return orc_end(); }
    WriteFile(first, "sharing", 7, &written, NULL);

    SetLastError(0);
    orc_kv("SECOND_OPEN_WHILE_EXCLUSIVE", "%s",
           try_open(GENERIC_READ, FILE_SHARE_READ) ? "opened" : "refused");
    orc_werr_now("SECOND_OPEN_WHILE_EXCLUSIVE_ERROR");

    SetLastError(0);
    orc_kv("DELETE_WHILE_OPEN", "%s", DeleteFileW(NAME) ? "deleted" : "refused");
    orc_werr_now("DELETE_WHILE_OPEN_ERROR");

    CloseHandle(first);

    /* Reopen, this time permitting readers but not writers. */
    first = CreateFileW(NAME, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL, NULL);
    orc_check("REOPEN_SHARING_READ", first != INVALID_HANDLE_VALUE);
    if (first == INVALID_HANDLE_VALUE) { orc_werr_now("REOPEN_ERROR"); return orc_end(); }

    /* A reader that also permits the writer already holding the file: allowed. */
    SetLastError(0);
    orc_kv("READER_WHILE_SHARE_READ", "%s",
           try_open(GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE)
           ? "opened" : "refused");
    orc_werr_now("READER_WHILE_SHARE_READ_ERROR");
    /* The same read access, but demanding that nobody may write: refused, because
     * somebody already may. This is the symmetric half of the check, and a layer
     * that only enforced the existing handle's share mode would let it through. */
    SetLastError(0);
    orc_kv("READER_WITH_INCOMPATIBLE_SHARE", "%s",
           try_open(GENERIC_READ, FILE_SHARE_READ) ? "opened" : "refused");
    orc_werr_now("READER_WITH_INCOMPATIBLE_SHARE_ERROR");
    SetLastError(0);
    orc_kv("WRITER_WHILE_SHARE_READ", "%s",
           try_open(GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE)
           ? "opened" : "refused");
    orc_werr_now("WRITER_WHILE_SHARE_READ_ERROR");
    CloseHandle(first);

    /* With nothing holding the file, even the strictest share mode opens it. */
    SetLastError(0);
    orc_kv("READER_AFTER_CLOSE", "%s",
           try_open(GENERIC_READ, 0) ? "opened" : "refused");
    orc_kv("WRITER_AFTER_CLOSE", "%s",
           try_open(GENERIC_WRITE, 0) ? "opened" : "refused");
    orc_check("DELETE_AFTER_CLOSE", DeleteFileW(NAME) != 0);
    orc_check("GONE", GetFileAttributesW(NAME) == INVALID_FILE_ATTRIBUTES);
    return orc_end();
}
