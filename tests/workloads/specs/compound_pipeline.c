/* A compound workload: a three-stage pipeline of re-executed copies of itself,
 * joined by anonymous pipes.
 *
 *   stage=produce   writes 256 KiB of deterministic bytes to stdout
 *   stage=transform reads stdin, rotates every byte, writes stdout
 *   stage=digest    reads stdin, writes the byte count and FNV-1a to a file
 *
 * The coordinator forks and execs all three, wires the pipes, waits for every
 * child, then verifies the digest file against the value it computed itself.
 * One specimen touching fork, exec, pipes, dup2, wait status, files and a
 * cross-process checksum at once. */
#include "oracle.h"
#include <sys/wait.h>
#include <unistd.h>

#define CHUNK (256u * 1024u)

static void produce(void) {
    unsigned long x = 0xDEADBEEFCAFEBABEUL;
    unsigned char b[4096];
    unsigned long done = 0;
    while (done < CHUNK) {
        size_t i;
        for (i = 0; i < sizeof b; i++) {
            x ^= x << 13; x ^= x >> 7; x ^= x << 17;
            b[i] = (unsigned char)(x & 0xff);
        }
        if (fwrite(b, 1, sizeof b, stdout) != sizeof b) _exit(120);
        done += (unsigned long)sizeof b;
    }
    fflush(stdout);
    _exit(0);
}

static void transform(void) {
    unsigned char b[4096];
    size_t n;
    while ((n = fread(b, 1, sizeof b, stdin)) > 0) {
        size_t i;
        for (i = 0; i < n; i++) b[i] = (unsigned char)((b[i] << 1) | (b[i] >> 7));
        if (fwrite(b, 1, n, stdout) != n) _exit(121);
    }
    fflush(stdout);
    _exit(0);
}

static void digest(void) {
    unsigned char b[4096];
    unsigned long h = 14695981039346656037UL, total = 0;
    size_t n;
    FILE *f;
    while ((n = fread(b, 1, sizeof b, stdin)) > 0) {
        size_t i;
        for (i = 0; i < n; i++) { h ^= (unsigned long)b[i]; h *= 1099511628211UL; }
        total += (unsigned long)n;
    }
    f = fopen("digest.out", "w");
    if (!f) _exit(122);
    fprintf(f, "%lu %016lx\n", total, h);
    fclose(f);
    _exit(0);
}

static unsigned long expected_hash(unsigned long *bytes_out) {
    unsigned long x = 0xDEADBEEFCAFEBABEUL;
    unsigned long h = 14695981039346656037UL, done = 0;
    while (done < CHUNK) {
        unsigned char c;
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        c = (unsigned char)(x & 0xff);
        c = (unsigned char)((c << 1) | (c >> 7));
        h ^= (unsigned long)c; h *= 1099511628211UL;
        done++;
    }
    *bytes_out = done;
    return h;
}

int main(int argc, char **argv) {
    int p1[2], p2[2];
    pid_t c1, c2, c3;
    int st1 = 0, st2 = 0, st3 = 0;
    unsigned long want_bytes = 0, want_hash;
    if (argc > 2 && strcmp(argv[1], "--stage") == 0) {
        if (strcmp(argv[2], "produce") == 0) produce();
        if (strcmp(argv[2], "transform") == 0) transform();
        if (strcmp(argv[2], "digest") == 0) digest();
        _exit(125);
    }
    orc_begin("linux-compound-pipeline");
    orc_kv("STAGES", "3");
    orc_kv("BYTES_PER_STAGE", "%u", CHUNK);
    orc_check("PIPES", pipe(p1) == 0 && pipe(p2) == 0);
    fflush(stdout);
    c1 = fork();
    if (c1 == 0) {
        char *av[4];
        dup2(p1[1], 1);
        close(p1[0]); close(p1[1]); close(p2[0]); close(p2[1]);
        av[0] = argv[0]; av[1] = (char *)"--stage"; av[2] = (char *)"produce"; av[3] = NULL;
        execv("/proc/self/exe", av);
        _exit(126);
    }
    c2 = fork();
    if (c2 == 0) {
        char *av[4];
        dup2(p1[0], 0); dup2(p2[1], 1);
        close(p1[0]); close(p1[1]); close(p2[0]); close(p2[1]);
        av[0] = argv[0]; av[1] = (char *)"--stage"; av[2] = (char *)"transform"; av[3] = NULL;
        execv("/proc/self/exe", av);
        _exit(126);
    }
    c3 = fork();
    if (c3 == 0) {
        char *av[4];
        dup2(p2[0], 0);
        close(p1[0]); close(p1[1]); close(p2[0]); close(p2[1]);
        av[0] = argv[0]; av[1] = (char *)"--stage"; av[2] = (char *)"digest"; av[3] = NULL;
        execv("/proc/self/exe", av);
        _exit(126);
    }
    close(p1[0]); close(p1[1]); close(p2[0]); close(p2[1]);
    waitpid(c1, &st1, 0); waitpid(c2, &st2, 0); waitpid(c3, &st3, 0);
    orc_kv("PRODUCE_EXIT", "%d", WIFEXITED(st1) ? WEXITSTATUS(st1) : -1);
    orc_kv("TRANSFORM_EXIT", "%d", WIFEXITED(st2) ? WEXITSTATUS(st2) : -1);
    orc_kv("DIGEST_EXIT", "%d", WIFEXITED(st3) ? WEXITSTATUS(st3) : -1);
    want_hash = expected_hash(&want_bytes);
    orc_kv("EXPECTED_BYTES", "%lu", want_bytes);
    orc_kv("EXPECTED_HASH", "%016lx", want_hash);
    {
        FILE *f = fopen("digest.out", "r");
        unsigned long got_bytes = 0;
        char got_hash[32];
        got_hash[0] = 0;
        orc_check("DIGEST_FILE_PRESENT", f != NULL);
        if (f) {
            if (fscanf(f, "%lu %31s", &got_bytes, got_hash) != 2) got_hash[0] = 0;
            fclose(f);
        }
        orc_kv("PIPELINE_BYTES", "%lu", got_bytes);
        orc_kv("PIPELINE_HASH", "%s", got_hash);
        {
            char want[32];
            snprintf(want, sizeof want, "%016lx", want_hash);
            orc_check("PIPELINE_HASH_MATCHES", strcmp(want, got_hash) == 0);
        }
        orc_check("PIPELINE_BYTES_MATCH", got_bytes == want_bytes);
    }
    return orc_end();
}
