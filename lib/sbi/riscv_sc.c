


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

static int _emulate_scprot(uint64_t addr, uint8_t perm, struct sbi_trap_regs *regs, unsigned long *tcause, unsigned long *tval) {
	int ci;
	uint64_t usid, desc[2], addr_vpn;
	char *ptable, *perms;
	uint32_t T, N;

	usid = csr_read(CSR_USID);
    addr_vpn = addr >> 12;

	ptable = (char *)(uintptr_t)((csr_read(CSR_SATP) & SATP32_PPN) << 12);
	T = ((uint32_t *)ptable)[1];
	N = ((uint32_t *)ptable)[3];

	perms = ptable + (16 * 64 * T) + (usid * 64 * T);
	ci = find_cell(ptable, desc, N, addr_vpn);

	/* ChecK: valid address */
	if(ci == N){
		*tcause = RISCV_EXCP_SECCELL_ILL_ADDR;
		*tval = addr;
		return -1;
	}
	/* Check: Valid cell */
	if(!(desc[1] & (1ul << 63))){
		*tcause = RISCV_EXCP_SECCELL_INV_CELL_STATE;
		*tval = 0;
		return -1;
	}

	uint8_t existing_perms = *(perms + ci);
    if(perm & ~RT_PERMS) {
		*tcause = RISCV_EXCP_SECCELL_ILL_PERM;
		*tval = (0 << 8) | (uint8_t)perm;
		return -1;
    } else if(perm & ~existing_perms) {
		*tcause = RISCV_EXCP_SECCELL_ILL_PERM;
		*tval = (2 << 8) | (uint8_t)perm;
		return -1;
	}
	*(perms + ci) = (existing_perms & (~0b1110ul)) | (perm & 0b1110ul);
	__asm__ __volatile("sfence.vma");

	return 0;
}

int emulate_scprot(ulong insn, struct sbi_trap_regs *regs) {
	uint64_t addr;
	uint8_t perm;
	struct sbi_trap_info trap;

	addr = GET_RS1(insn, regs);
	perm = GET_RS2(insn, regs);

	trap.epc = regs->mepc;
	trap.tval2 = 0;
	trap.tinst = 0;

	if(_emulate_scprot(addr, perm, regs, &trap.cause, &trap.tval)) 
        return sbi_trap_redirect(regs, &trap);
    
    regs->mepc += 4;
	
	return 0;
}

int __attribute__((noinline)) emulate_scinval(ulong insn, struct sbi_trap_regs *regs) {
	int ci, sd;
	struct sbi_trap_info trap;
	uint64_t addr, addr_vpn, desc[2], usid;
	char *ptable;
	uint32_t __attribute__((unused)) N, T, R, M, pperm, gperm;

	trap.epc = regs->mepc;
	trap.tval2 = 0;
	trap.tinst = 0;

	addr_vpn = (addr = GET_RS1(insn, regs)) >> 12;
	usid = csr_read(CSR_USID);
	ptable = (char *)(uintptr_t)((csr_read(CSR_SATP) & SATP32_PPN) << 12);
	N = ((uint32_t *)ptable)[3];
	M = ((uint32_t *)ptable)[2];
	T = ((uint32_t *)ptable)[1];
	R = ((uint32_t *)ptable)[0];
	
	ci = find_cell(ptable, desc, N, addr_vpn);

	/* ChecK: valid address */
	if(ci == N){
		trap.cause = RISCV_EXCP_SECCELL_ILL_ADDR;
		trap.tval = addr;
		return sbi_trap_redirect(regs, &trap);
	}
	/* Check: Already inValid cell */
	if(!(desc[1] & (1ull << 63))){
		trap.cause = RISCV_EXCP_SECCELL_INV_CELL_STATE;
		trap.tval = 0;
		return sbi_trap_redirect(regs, &trap);
	}

	for(sd = 1; sd < M; sd++) {
		if(sd != usid) {
			pperm = *(PT(ptable, T, sd, ci));
			if((pperm & RT_PERMS) != 0) {
                trap.cause = RISCV_EXCP_SECCELL_INV_CELL_STATE;
                trap.tval = 2;
				return sbi_trap_redirect(regs, &trap);
			}

			gperm = *(GT(ptable, R, T, sd, ci));
			if(gperm != G(SDINV, 0)) {
                trap.cause = RISCV_EXCP_SECCELL_INV_CELL_STATE;
                trap.tval = 3;
				return sbi_trap_redirect(regs, &trap);
			}
		}
	}

    *(PT(ptable, T, usid, ci)) = RT_D | RT_A;
    *(PT(ptable, T, 0, ci)) &= ~RT_V;

	desc[1] &= ~(1ul << 63);
	((uint64_t *)(ptable + (ci * 2 * sizeof(uint64_t))))[1] = desc[1];
	__asm__ __volatile("sfence.vma");

	regs->mepc += 4;
	return 0;
}


int emulate_screval(ulong insn, struct sbi_trap_regs *regs) {
	int ci;
	struct sbi_trap_info trap;
	uint64_t addr, addr_vpn, perm, usid, desc[2];
	char *ptable;
	uint32_t T, N;

	trap.epc = regs->mepc;
	trap.tval2 = 0;
	trap.tinst = 0;

	addr_vpn = (addr = GET_RS1(insn, regs)) >> 12;
	perm = GET_RS2(insn, regs);
	usid = csr_read(CSR_USID);

	ptable = (char *)(uintptr_t)((csr_read(CSR_SATP) & SATP32_PPN) << 12);
	T = ((uint32_t *)ptable)[1];
	N = ((uint32_t *)ptable)[3];
	
    if(perm & ~RT_PERMS) {
		trap.cause = RISCV_EXCP_SECCELL_ILL_PERM;
		trap.tval = (0 << 8) | (uint8_t)perm;
		return sbi_trap_redirect(regs, &trap);
	} else if (!perm) {
		trap.cause = RISCV_EXCP_SECCELL_ILL_PERM;
		trap.tval = (1 << 8) | (uint8_t)perm;
		return sbi_trap_redirect(regs, &trap);
    }

	ci = find_cell(ptable, desc, N, addr_vpn);
	/* ChecK: valid address */
	if(ci == N){
		trap.cause = RISCV_EXCP_SECCELL_ILL_ADDR;
		trap.tval = addr;
		return sbi_trap_redirect(regs, &trap);
	}
	/* Check: Already Valid cell */
	if(desc[1] & (1ul << 63)){
		trap.cause = RISCV_EXCP_SECCELL_INV_CELL_STATE;
		trap.tval = 1;
		return sbi_trap_redirect(regs, &trap);
	}

	desc[1] |= (1ul << 63);

    *(PT(ptable, T, 0, ci)) |= RT_V;

	*(ptable + (16 * 64 * T) + (usid * 64 * T) + ci) = RT_D | RT_A | perm | RT_V;
	((uint64_t *)(ptable + (ci * 2 * sizeof(uint64_t))))[1] = desc[1];
	__asm__ __volatile("sfence.vma");

	regs->mepc += 4;
	return 0;
}

int emulate_scgrant(ulong insn, struct sbi_trap_regs *regs) {
	int ci;
	uint64_t desc[2], addr, addr_vpn, sdtgt, usid;
	char *ptable, perm, existing_perms;
	uint32_t N, T, R, M;
	struct sbi_trap_info trap;

	trap.epc = regs->mepc;
	trap.tval2 = 0;
	trap.tinst = 0;

	addr_vpn = (addr = GET_RS1(insn, regs)) >> 12;
	sdtgt = GET_RS2(insn, regs);
	perm = IMM_S(insn);
	usid = csr_read(CSR_USID);

	if(perm & ~RT_PERMS) {
		trap.cause = RISCV_EXCP_SECCELL_ILL_PERM;
		trap.tval = (0 << 8) | (uint8_t)perm;
		return sbi_trap_redirect(regs, &trap);
    } else if((perm & RT_PERMS) == 0) {
		trap.cause = RISCV_EXCP_SECCELL_ILL_PERM;
		trap.tval = (1 << 8) | (uint8_t)perm;
		return sbi_trap_redirect(regs, &trap);
	}

	ptable = (char *)(uintptr_t)((csr_read(CSR_SATP) & SATP32_PPN) << 12);
	R = ((uint32_t *)ptable)[0];
	T = ((uint32_t *)ptable)[1];
	M = ((uint32_t *)ptable)[2];
	N = ((uint32_t *)ptable)[3];

	if((sdtgt == 0) || (sdtgt > M)) {
		trap.cause = RISCV_EXCP_SECCELL_INV_SDID;
		trap.tval = sdtgt;
		return sbi_trap_redirect(regs, &trap);
	}

	ci = find_cell(ptable, desc, N, addr_vpn);
	/* ChecK: valid address */
	if(ci == N){
		trap.cause = RISCV_EXCP_SECCELL_ILL_ADDR;
		trap.tval = addr;
		return sbi_trap_redirect(regs, &trap);
	}
	/* Check: For Valid cell */
	if(!(desc[1] & (1ul << 63))) {
		trap.cause = RISCV_EXCP_SECCELL_INV_CELL_STATE;
		trap.tval = 0;
		return sbi_trap_redirect(regs, &trap);
	}

	existing_perms = *(PT(ptable, T, usid, ci));
	if(perm & ~existing_perms) {
		trap.cause = RISCV_EXCP_SECCELL_ILL_PERM;
		trap.tval = (2 << 8) | (uint8_t)perm;
		return sbi_trap_redirect(regs, &trap);
	}

	*GT(ptable, R, T, usid, ci) = G(sdtgt, perm);
	__asm__ __volatile("sfence.vma");

	regs->mepc += 4;
	return 0;
}


int emulate_screcv(ulong insn, struct sbi_trap_regs *regs) {
	int ci;
	uint64_t desc[2], addr, addr_vpn, sdsrc, usid;
	char *ptable, perm, existing_perms;
	uint32_t M, N, T, R, grant;
	struct sbi_trap_info trap;

	trap.epc = regs->mepc;
	trap.tval2 = 0;
	trap.tinst = 0;

	addr_vpn = (addr = GET_RS1(insn, regs)) >> 12;
	sdsrc = GET_RS2(insn, regs);
	perm = IMM_S(insn);
	usid = csr_read(CSR_USID);

	if(perm & ~RT_PERMS) {
		trap.cause = RISCV_EXCP_SECCELL_ILL_PERM;
		trap.tval = (0 << 8) | (uint8_t)perm;
		return sbi_trap_redirect(regs, &trap);
    } else if((perm & RT_PERMS) == 0) {
		trap.cause = RISCV_EXCP_SECCELL_ILL_PERM;
		trap.tval = (1 << 8) | (uint8_t)perm;
		return sbi_trap_redirect(regs, &trap);
	}

	ptable = (char *)(uintptr_t)((csr_read(CSR_SATP) & SATP32_PPN) << 12);
	R = ((uint32_t *)ptable)[0];
	T = ((uint32_t *)ptable)[1];
	M = ((uint32_t *)ptable)[2];
	N = ((uint32_t *)ptable)[3];


	if((sdsrc == 0) || (sdsrc > M)) {
		trap.cause = RISCV_EXCP_SECCELL_INV_SDID;
		trap.tval = sdsrc;
		return sbi_trap_redirect(regs, &trap);
	}

	ci = find_cell(ptable, desc, N, addr_vpn);
	/* ChecK: valid address */
	if(ci == N){
		trap.cause = RISCV_EXCP_SECCELL_ILL_ADDR;
		trap.tval = addr;
		return sbi_trap_redirect(regs, &trap);
	}
	/* Check: For Valid cell */
	if(!(desc[1] & (1ul << 63))) {
		trap.cause = RISCV_EXCP_SECCELL_INV_CELL_STATE;
		trap.tval = 0;
		return sbi_trap_redirect(regs, &trap);
	}

	grant = *(GT(ptable, R, T, sdsrc, ci));
	existing_perms = *(PT(ptable, T, usid, ci));

	if((grant >> 4) != usid){
		// trap.cause;
		// trap.tval;
		return sbi_trap_redirect(regs, &trap);
	}
	if(perm & ~(grant & RT_PERMS)) {
		// trap.cause;
		// trap.tval;
		return sbi_trap_redirect(regs, &trap);
	}

	if(perm == (grant & RT_PERMS)) 
		*(GT(ptable, R, T, sdsrc, ci)) = G(SDINV, 0);
	else 
		*(GT(ptable, R, T, sdsrc, ci)) = G(sdsrc, ((grant & RT_PERMS) & ~perm));
	*(PT(ptable, T, usid, ci)) = existing_perms | perm | RT_V;
	__asm__ __volatile("sfence.vma");

	regs->mepc += 4;
	return 0;
}

int emulate_sctfer(ulong insn, struct sbi_trap_regs *regs) {
	uint64_t addr;
	uint32_t grantinsn;
	struct sbi_trap_info trap;

	trap.epc = regs->mepc;
	trap.tval2 = 0;
	trap.tinst = 0;

	addr = GET_RS1(insn, regs);

	grantinsn = (insn & ~(MASK_TFER)) | MATCH_GRANT;
	emulate_scgrant(grantinsn, regs);

	if(_emulate_scprot(addr, 0, regs, &trap.cause, &trap.tval)) 
        return sbi_trap_redirect(regs, &trap);

	__asm__ __volatile("sfence.vma");
	regs->mepc += 4;
	return 0;
}

int emulate_scexcl(ulong insn, struct sbi_trap_regs *regs) {
	uint64_t addr, addr_vpn, desc[2], usid;
	uint32_t gperm;
	uint8_t perm, existing_perms, pperm;
	char *ptable;
	int R, T, M, N, ci, sd;
	struct sbi_trap_info trap;

	trap.epc = regs->mepc;
	trap.tval2 = 0;
	trap.tinst = 0;

	addr = GET_RS1(insn, regs);
	perm = GET_RS2(insn, regs);
	addr_vpn = addr >> 12;
	usid = csr_read(CSR_USID);

	ptable = (char *)(uintptr_t)((csr_read(CSR_SATP) & SATP32_PPN) << 12);
	R = ((uint32_t *)ptable)[0];
	T = ((uint32_t *)ptable)[1];
	M = ((uint32_t *)ptable)[2];
	N = ((uint32_t *)ptable)[3];


	ci = find_cell(ptable, desc, N, addr_vpn);
	/* ChecK: valid address */
	if(ci == N){
		trap.cause = RISCV_EXCP_SECCELL_ILL_ADDR;
		trap.tval = addr;
		return sbi_trap_redirect(regs, &trap);
	}
	/* Check: For Valid cell */
	if(!(desc[1] & (1ul << 63))) {
		trap.cause = RISCV_EXCP_SECCELL_INV_CELL_STATE;
		trap.tval = 0;
		return sbi_trap_redirect(regs, &trap);
	}

	existing_perms = *(PT(ptable, T, usid, ci));
    if(perm & ~RT_PERMS) {
		trap.cause = RISCV_EXCP_SECCELL_ILL_PERM;
		trap.tval = (0 << 8) | (uint8_t)perm;
		return -1;
    } else if((perm & RT_PERMS) == 0) {
		trap.cause = RISCV_EXCP_SECCELL_ILL_PERM;
		trap.tval = (1 << 8) | (uint8_t)perm;
		return sbi_trap_redirect(regs, &trap);
	}else if(perm & ~existing_perms) {
		trap.cause = RISCV_EXCP_SECCELL_ILL_PERM;
		trap.tval = (2 << 8) | (uint8_t)perm;
		return -1;
	}

	for(sd = 1; sd < M; sd++) {
		if(sd != usid) {
			pperm = *(PT(ptable, T, sd, ci));
			gperm = *(GT(ptable, R, T, sd, ci));
			if(((pperm & RT_PERMS) != 0) || (gperm != G(SDINV, 0))) 
				break;
		}
	}
	if (sd == M) /* Case: Exclusive */
		SET_RD(insn, regs, 0);
	else
		SET_RD(insn, regs, 1);

	regs->mepc += 4;
	return 0;
}
