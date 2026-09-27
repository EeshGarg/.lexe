/* A Windows named pipe, which has no POSIX equivalent worth pretending about:
 * the main thread serves \\.\\pipe\\lexe-workload-<pid> and a worker thread
 * connects as a client and exchanges one message. The pipe name carries the
 * process id so parallel runs cannot collide. */
#include "oracle_win.h"

static wchar_t pipe_name[128];
static volatile LONG client_result = -1;

static DWORD WINAPI client(LPVOID unused) {
    HANDLE h;
    DWORD written = 0, read_back = 0;
    char buf[32];
    (void)unused;
    if (!WaitNamedPipeW(pipe_name, 10000)) { client_result = 10; return 0; }
    h = CreateFileW(pipe_name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) { client_result = 11; return 0; }
    if (!WriteFile(h, "PIPE-PING", 9, &written, NULL)) { client_result = 12; CloseHandle(h); return 0; }
    if (!ReadFile(h, buf, sizeof buf - 1, &read_back, NULL)) { client_result = 13; CloseHandle(h); return 0; }
    buf[read_back] = 0;
    client_result = (strcmp(buf, "PIPE-PONG") == 0) ? 0 : 14;
    CloseHandle(h);
    return 0;
}

int main(void) {
    HANDLE srv, th;
    DWORD read_back = 0, written = 0;
    char buf[32];
    orc_begin("pe-ipc-named-pipe");
    _snwprintf(pipe_name, 128, L"\\\\.\\pipe\\lexe-workload-%lu",
               (unsigned long)GetCurrentProcessId());
    srv = CreateNamedPipeW(pipe_name, PIPE_ACCESS_DUPLEX,
                           PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                           1, 4096, 4096, 5000, NULL);
    orc_check("CREATE_NAMED_PIPE", srv != INVALID_HANDLE_VALUE);
    if (srv == INVALID_HANDLE_VALUE) { orc_werr_now("CREATE_ERROR"); return orc_end(); }
    th = CreateThread(NULL, 0, client, NULL, 0, NULL);
    orc_check("CLIENT_THREAD", th != NULL);
    orc_check("CONNECT_NAMED_PIPE",
              ConnectNamedPipe(srv, NULL) != 0 || GetLastError() == ERROR_PIPE_CONNECTED);
    if (!ReadFile(srv, buf, sizeof buf - 1, &read_back, NULL)) {
        orc_check("SERVER_READ", 0);
        orc_werr_now("READ_ERROR");
    } else {
        buf[read_back] = 0;
        orc_check("SERVER_READ", 1);
        orc_kv("SERVER_RECEIVED", "%s", buf);
        orc_check("PING_CORRECT", strcmp(buf, "PIPE-PING") == 0);
        orc_check("SERVER_WRITE", WriteFile(srv, "PIPE-PONG", 9, &written, NULL) != 0);
        FlushFileBuffers(srv);
    }
    if (th) { WaitForSingleObject(th, 30000); CloseHandle(th); }
    orc_kv("CLIENT_RESULT", "%ld", (long)client_result);
    orc_check("CLIENT_ROUNDTRIP_OK", client_result == 0);
    DisconnectNamedPipe(srv);
    CloseHandle(srv);
    return orc_end();
}
