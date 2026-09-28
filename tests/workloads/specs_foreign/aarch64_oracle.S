/* AArch64 oracle specimen -- a complete, legitimate Linux/AArch64 program.
 *
 * WHAT THIS IS
 *   Freestanding AArch64: no libc, no dynamic loader, no relocations. It writes
 *   its KEY=VALUE oracle stream to fd 1 with the Linux write(2) syscall and then
 *   exits 0 through exit_group(2). On a Linux/AArch64 host this runs and prints
 *   the lines below; there is nothing conditional or host-specific about it.
 *
 * WHY IT IS WRITTEN IN ASSEMBLY, AND WHY THERE ARE NO RELOCATIONS
 *   This host (x86-64) has clang with the aarch64 target, so it can ASSEMBLE
 *   genuine AArch64 instructions -- but nothing here can LINK them: GNU ld has
 *   no aarch64linux emulation, ld.gold rejects ELF machine 183, and lld is not
 *   installed. generate_foreign.py therefore performs the link itself: it reads
 *   the .text section straight out of clang's object file and writes an ELF
 *   header plus one PT_LOAD around it.
 *
 *   That substitution is only honest if there is nothing left for a linker to
 *   do, so every address here is PC-relative (`adr`) and every operand is an
 *   immediate. The generator ASSERTS that the object contains no relocations
 *   against .text and fails rather than resolving one by hand. If a future
 *   change to this file introduces a relocation, the fixture stops building --
 *   which is the intended outcome, not a regression to work around.
 *
 * WHAT IT DOES NOT PROVE
 *   Nothing about AArch64 support anywhere. It cannot be executed on this host
 *   and carries no direct-execution baseline. Its only verified facts are
 *   structural, plus the measured refusal when this host is asked to run it.
 *
 * Deterministic oracle stream (byte for byte, on a Linux/AArch64 host):
 *   FIXTURE_ID=linux-foreign-aarch64-exec
 *   ARCH_DECLARED=aarch64
 *   SYSCALL_ABI=linux-aarch64-svc0
 *   LINKED_BY=generate_foreign.py
 *   RELOCATIONS=none
 *   WROTE_ORACLE=yes
 *   RESULT=PASS
 */

	.arch	armv8-a
	.text
	.globl	_start
_start:
	/* write(1, oracle, oracle_end - oracle) */
	mov	x0, #1
	adr	x1, oracle		/* PC-relative: no relocation */
	adr	x2, oracle_end		/* PC-relative: no relocation */
	sub	x2, x2, x1
	mov	x8, #64			/* __NR_write */
	svc	#0

	/* A short write or an error is a failure of the environment, not of the
	 * program, and it must not be reported as success. */
	adr	x2, oracle_end
	adr	x1, oracle
	sub	x1, x2, x1
	cmp	x0, x1
	b.ne	.Lshort

	mov	x0, #0			/* exit_group(0) */
	mov	x8, #94
	svc	#0

.Lshort:
	mov	x0, #9			/* exit_group(9): wrote, but not all of it */
	mov	x8, #94
	svc	#0
	brk	#0			/* unreachable: exit_group does not return */

	.balign	8
oracle:
	.ascii	"FIXTURE_ID=linux-foreign-aarch64-exec\n"
	.ascii	"ARCH_DECLARED=aarch64\n"
	.ascii	"SYSCALL_ABI=linux-aarch64-svc0\n"
	.ascii	"LINKED_BY=generate_foreign.py\n"
	.ascii	"RELOCATIONS=none\n"
	.ascii	"WROTE_ORACLE=yes\n"
	.ascii	"RESULT=PASS\n"
oracle_end:
