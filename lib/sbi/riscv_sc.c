


#include <string.h>
#include <inttypes.h>
#include <sbi/riscv_asm.h>
#include <sbi/riscv_sc.h>

static inline int find_cell(char *ptable, uint64_t *desc, int N, uint64_t addr_vpn) {
	int i;
	uint64_t vpn_start, vpn_end;

	for(i = 1; i < N; i++) {
		memcpy(desc, ptable + (i * 2 * sizeof(uint64_t)), 2 * sizeof(uint64_t));
		vpn_start = (desc[0] & ((1ul << 36) - 1));
		vpn_end = ((desc[1] & 0xff) << 28) | (desc[0] >> 36);
		if((vpn_start <= addr_vpn) && (addr_vpn <= vpn_end))
			break;
	}

	return i;
}

static int _emulate_scprot(uint64_t addr_vpn, uint8_t perm, struct sbi_trap_regs *regs) {
	int ci;
	struct sbi_trap_info trap;
	uint64_t usid, desc[2];
	char *ptable, *perms;
	uint32_t T, N;

	trap.epc = regs->mepc;
	trap.tval2 = 0;
	trap.tinst = 0;

	usid = csr_read(CSR_USID);

	ptable = (char *)(uintptr_t)((csr_read(CSR_SATP) & SATP32_PPN) << 12);
	T = ((uint32_t *)ptable)[1];
	N = ((uint32_t *)ptable)[3];

	perms = ptable + (16 * 64 * T) + (usid * 64 * T);
	ci = find_cell(ptable, desc, N, addr_vpn);

	/* ChecK: valid address */
	if(ci == N){
		// trap.cause;
		// trap.tval;
		return sbi_trap_redirect(regs, &trap);
	}
	/* Check: Valid cell */
	if(!(desc[1] & (1ul << 63))){
		// trap.cause;
		// trap.tval;
		return sbi_trap_redirect(regs, &trap);
	}

	uint8_t existing_perms = *(perms + ci);
	if(perm & ~existing_perms) {
		// trap.cause;
		// trap.tval;
		return sbi_trap_redirect(regs, &trap);
	}
	*(perms + ci) = (existing_perms & (~0b1110ul)) | (perm & 0b1110ul);
	__asm__ __volatile("sfence.vma");

	return 0;
}

int emulate_scprot(ulong insn, struct sbi_trap_regs *regs) {
	uint64_t addr_vpn;
	uint8_t perm;

	addr_vpn = GET_RS1(insn, regs) >> 12;
	perm = GET_RS2(insn, regs);

	int ret = _emulate_scprot(addr_vpn, perm, regs);
	if(ret == 0) 
		regs->mepc += 4;
	
	return ret;
}

int __attribute__((noinline)) emulate_scinval(ulong insn, struct sbi_trap_regs *regs) {
	int ci, sd;
	struct sbi_trap_info trap;
	uint64_t addr_vpn, desc[2], usid;
	char *ptable;
	uint32_t __attribute__((unused)) N, T, R, M, pperm, gperm;

	trap.epc = regs->mepc;
	trap.tval2 = 0;
	trap.tinst = 0;

	addr_vpn = GET_RS1(insn, regs) >> 12;
	usid = csr_read(CSR_USID);
	ptable = (char *)(uintptr_t)((csr_read(CSR_SATP) & SATP32_PPN) << 12);
	N = ((uint32_t *)ptable)[3];
	M = ((uint32_t *)ptable)[2];
	T = ((uint32_t *)ptable)[1];
	R = ((uint32_t *)ptable)[0];
	
	ci = find_cell(ptable, desc, N, addr_vpn);

	/* ChecK: valid address */
	if(ci == N){
		// trap.cause;
		// trap.tval;
		return sbi_trap_redirect(regs, &trap);
	}
	/* Check: Already inValid cell */
	if(!(desc[1] & (1ull << 63))){
		// trap.cause;
		// trap.tval;
		return sbi_trap_redirect(regs, &trap);
	}

	for(sd = 1; sd < M; sd++) {
		if(sd != usid) {
			pperm = *(PT(ptable, T, sd, ci));
			if((pperm & 0xe) != 0) {
				// trap.cause;
				// trap.tval;
				return sbi_trap_redirect(regs, &trap);
			}

			gperm = *(GT(ptable, R, T, sd, ci));
			if(gperm != G(-1, 0)) {
			// 	// trap.cause;
			// 	// trap.tval;
				return sbi_trap_redirect(regs, &trap);
			}
		}
	}

	desc[1] &= ~(1ul << 63);
	((uint64_t *)(ptable + (ci * 2 * sizeof(uint64_t))))[1] = desc[1];
	__asm__ __volatile("sfence.vma");

	regs->mepc += 4;
	return 0;
}


int emulate_screval(ulong insn, struct sbi_trap_regs *regs) {
	int ci;
	struct sbi_trap_info trap;
	uint64_t addr_vpn, perm, usid, desc[2];
	char *ptable;
	uint32_t T, N;

	trap.epc = regs->mepc;
	trap.tval2 = 0;
	trap.tinst = 0;

	addr_vpn = GET_RS1(insn, regs) >> 12;
	perm = GET_RS2(insn, regs);
	usid = csr_read(CSR_USID);

	ptable = (char *)(uintptr_t)((csr_read(CSR_SATP) & SATP32_PPN) << 12);
	T = ((uint32_t *)ptable)[1];
	N = ((uint32_t *)ptable)[3];
	
	ci = find_cell(ptable, desc, N, addr_vpn);
	/* ChecK: valid address */
	if(ci == N){
		// trap.cause;
		// trap.tval;
		return sbi_trap_redirect(regs, &trap);
	}
	/* Check: Already Valid cell */
	if(desc[1] & (1ul << 63)){
		// trap.cause;
		// trap.tval;
		return sbi_trap_redirect(regs, &trap);
	}

	desc[1] |= (1ul << 63);

	*(ptable + (16 * 64 * T) + (usid * 64 * T) + ci) = 0xc1 | perm;
	((uint64_t *)(ptable + (ci * 2 * sizeof(uint64_t))))[1] = desc[1];
	__asm__ __volatile("sfence.vma");

	regs->mepc += 4;
	return 0;
}

int emulate_scgrant(ulong insn, struct sbi_trap_regs *regs) {
	int ci;
	uint64_t desc[2], addr_vpn, sdtgt, usid;
	char *ptable, perm, existing_perms;
	uint32_t N, T, R;
	struct sbi_trap_info trap;

	trap.epc = regs->mepc;
	trap.tval2 = 0;
	trap.tinst = 0;

	addr_vpn = GET_RS1(insn, regs) >> 12;
	sdtgt = GET_RS2(insn, regs);
	perm = IMM_S(insn);
	usid = csr_read(CSR_USID);

	if((perm & 0xe) == 0) {
		// trap.cause;
		// trap.tval;
		return sbi_trap_redirect(regs, &trap);
	}

	ptable = (char *)(uintptr_t)((csr_read(CSR_SATP) & SATP32_PPN) << 12);
	R = ((uint32_t *)ptable)[0];
	T = ((uint32_t *)ptable)[1];
	N = ((uint32_t *)ptable)[3];

	ci = find_cell(ptable, desc, N, addr_vpn);
	/* ChecK: valid address */
	if(ci == N){
		// trap.cause;
		// trap.tval;
		return sbi_trap_redirect(regs, &trap);
	}
	/* Check: Already Valid cell */
	if(!(desc[1] & (1ul << 63))) {
		// trap.cause;
		// trap.tval;
		return sbi_trap_redirect(regs, &trap);
	}

	existing_perms = *(PT(ptable, T, usid, ci));
	if(perm & ~existing_perms) {
		// trap.cause;
		// trap.tval;
		return sbi_trap_redirect(regs, &trap);
	}

	*GT(ptable, R, T, usid, ci) = G(sdtgt, perm);
	__asm__ __volatile("sfence.vma");

	regs->mepc += 4;
	return 0;
}


int emulate_screcv(ulong insn, struct sbi_trap_regs *regs) {
	int ci;
	uint64_t desc[2], addr_vpn, sdsrc, usid;
	char *ptable, perm, existing_perms;
	uint32_t N, T, R, grant;
	struct sbi_trap_info trap;

	trap.epc = regs->mepc;
	trap.tval2 = 0;
	trap.tinst = 0;

	addr_vpn = GET_RS1(insn, regs) >> 12;
	sdsrc = GET_RS2(insn, regs);
	perm = IMM_S(insn);
	usid = csr_read(CSR_USID);

	if((perm & 0xe) == 0) {
		// trap.cause;
		// trap.tval;
		return sbi_trap_redirect(regs, &trap);
	}

	ptable = (char *)(uintptr_t)((csr_read(CSR_SATP) & SATP32_PPN) << 12);
	R = ((uint32_t *)ptable)[0];
	T = ((uint32_t *)ptable)[1];
	N = ((uint32_t *)ptable)[3];

	ci = find_cell(ptable, desc, N, addr_vpn);
	/* ChecK: valid address */
	if(ci == N){
		// trap.cause;
		// trap.tval;
		return sbi_trap_redirect(regs, &trap);
	}
	/* Check: Already Valid cell */
	if(!(desc[1] & (1ul << 63))) {
		// trap.cause;
		// trap.tval;
		return sbi_trap_redirect(regs, &trap);
	}

	grant = *(GT(ptable, R, T, sdsrc, ci));
	existing_perms = *(PT(ptable, T, usid, ci));

	if((grant >> 3) != usid){
		// trap.cause;
		// trap.tval;
		return sbi_trap_redirect(regs, &trap);
	}
	if(perm & ~(grant & 0x7)) {
		// trap.cause;
		// trap.tval;
		return sbi_trap_redirect(regs, &trap);
	}

	if(perm == (grant & 0x7)) 
		*(GT(ptable, R, T, sdsrc, ci)) = G(-1, 0);
	else 
		*(GT(ptable, R, T, sdsrc, ci)) = G(sdsrc, ((grant & 0x7) & ~perm));
	*(PT(ptable, T, usid, ci)) = existing_perms | perm;
	__asm__ __volatile("sfence.vma");

	regs->mepc += 4;
	return 0;
}

int emulate_sctfer(ulong insn, struct sbi_trap_regs *regs) {
	uint64_t addr_vpn;
	uint32_t grantinsn;

	addr_vpn = GET_RS1(insn, regs);

	grantinsn = (insn & ~(MASK_TFER)) | MATCH_GRANT;
	emulate_scgrant(grantinsn, regs);

	_emulate_scprot(addr_vpn, 0, regs);
	__asm__ __volatile("sfence.vma");

	regs->mepc += 4;
	return 0;
}