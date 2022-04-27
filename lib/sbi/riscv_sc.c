


#include <string.h>
#include <inttypes.h>
#include <sbi/riscv_asm.h>
#include <sbi/riscv_sc.h>

static inline  uint64_t get_rs1() {
	uint64_t rs1;
	asm volatile("csrr %[rs1], mtirs1"
							: [rs1] "=r" (rs1));

	return rs1;
}

static inline  uint64_t get_rs2() {
	uint64_t rs2;
	asm volatile("csrr %[rs2], mtirs2"
							: [rs2] "=r" (rs2));

	return rs2;
}

static inline  uint64_t get_imm() {
	uint64_t imm;
	asm volatile("csrr %[imm], mtiimm"
							: [imm] "=r" (imm));

	return imm;
}

static inline void set_rd(uint64_t val) {
	asm volatile("csrw mtirdval, %[rdval]"
							:: [rdval] "r" (val));
}

static int64_t sccck(uint64_t va, uint64_t v) {
	int64_t i;
	asm volatile ("sccck %0, %1, %2\n"
				 : "=r" (i)
				 : "r"  (va), "r" (v));
	return i;
}

static uint64_t *scca(int64_t ci) {
	uint64_t *p;
	asm volatile ("scca %0, %1\n"
				 : "=r" (p)
				 : "r"  (ci));
	return p;
}

static uint8_t  *scpa(int64_t ci, uint64_t sd) {
	uint8_t  *p;
	asm volatile ("scpa %0, %1, %2\n"
				 : "=r" (p)
				 : "r"  (ci), "r" (sd));
	return p;
}

static uint32_t *scga(int64_t ci, uint64_t sd) {
	uint32_t *p;
	asm volatile ("scga %0, %1, %2\n"
				 : "=r" (p)
				 : "r"  (ci), "r" (sd));
	return p;
}

static inline int64_t find_cell(uint64_t *desc, uint64_t addr, uint64_t v) {
	int64_t i = sccck(addr, v);
	if (i > 0)
		memcpy(desc, scca(i), 2 * sizeof(uint64_t));
	return i;
}

static inline int _emulate_scprot(uint64_t addr, uint8_t perm, 
														struct sbi_trap_regs *regs, 
														unsigned long *tcause, 
														unsigned long *tval) {
	int64_t ci = sccck(addr, 1);

	/* ChecK: valid address */
	if(unlikely(ci < 0)) {
		*tcause = RISCV_EXCP_SECCELL_ILL_ADDR;
		*tval = addr;
		return -1;
	} else if(unlikely(ci == 0)) {
		/* Check: Valid cell */
		*tcause = RISCV_EXCP_SECCELL_INV_CELL_STATE;
		*tval = 0;
		return -1;
	}

	uint8_t *perms = scpa(ci, 0);
	uint8_t existing_perms = *perms;
  if(unlikely(perm & ~RT_PERMS)) {
		*tcause = RISCV_EXCP_SECCELL_ILL_PERM;
		*tval = (0 << 8) | (uint8_t)perm;
		return -1;
  } else if(unlikely(perm & ~existing_perms)) {
		*tcause = RISCV_EXCP_SECCELL_ILL_PERM;
		*tval = (2 << 8) | (uint8_t)perm;
		return -1;
	}

	*perms = (existing_perms & (~RT_PERMS)) | (perm & RT_PERMS);
	__asm__ __volatile("sfence.vma");

	return 0;
}

int emulate_scprot(struct sbi_trap_regs *regs) {
	uint64_t addr;
	uint8_t perm;
	struct sbi_trap_info trap;

	addr = get_rs1();
	perm = get_rs2();

	if(unlikely(_emulate_scprot(addr, perm, regs, &trap.cause, &trap.tval))) {
		trap.epc = regs->mepc;
		trap.tval2 = 0;
		trap.tinst = 0;
    return sbi_trap_redirect(regs, &trap);
	}

	regs->mepc += 4;
	return 0;
}

int emulate_scinval(struct sbi_trap_regs *regs) {
	int64_t ci;
	struct sbi_trap_info trap;
	uint64_t sd, addr, usid;
	uint8_t *ptable;
	uint32_t M;

	addr = get_rs1();
	usid = csr_read(CSR_USID);

	ptable = (uint8_t *)(uintptr_t)((csr_read(CSR_SATP) & SATP64_PPN) << 12);
	M = ((uint32_t *)ptable)[2];

	ci = sccck(addr, 1);

	/* ChecK: valid address */
	if (unlikely(ci < 0)) {
		trap.epc = regs->mepc;
		trap.cause = RISCV_EXCP_SECCELL_ILL_ADDR;
		trap.tval = addr;
		return sbi_trap_redirect(regs, &trap);
	} else if (unlikely(ci == 0)) {
	/* Check: Already inValid cell */
		trap.epc = regs->mepc;
		trap.cause = RISCV_EXCP_SECCELL_INV_CELL_STATE;
		trap.tval = 0;
		return sbi_trap_redirect(regs, &trap);
	}

	for(sd = 1; sd < M; sd++) {
		if(sd != usid) {
			uint8_t pperm = *scpa(ci, sd);
			if(unlikely((pperm & RT_PERMS) != 0)) {
				trap.epc = regs->mepc;
				trap.cause = RISCV_EXCP_SECCELL_INV_CELL_STATE;
				trap.tval = 2;
				return sbi_trap_redirect(regs, &trap);
			}

			uint32_t gperm = *scga(ci, sd);
			if(unlikely(gperm != G(SDINV, 0))) {
				trap.epc = regs->mepc;
				trap.cause = RISCV_EXCP_SECCELL_INV_CELL_STATE;
				trap.tval = 3;
				return sbi_trap_redirect(regs, &trap);
			}
		}
	}

	*scpa(ci, 0) = RT_D | RT_A;
	*scpa(ci, (uint64_t)(-1l)) &= ~RT_V;

	scca(ci)[1] &= ~(1ul << 63);
	__asm__ __volatile("sfence.vma");

	regs->mepc += 4;
	return 0;
}

int emulate_screval(struct sbi_trap_regs *regs) {
	int64_t ci;
	struct sbi_trap_info trap;
	uint64_t addr, perm;

	addr = get_rs1();
	perm = get_rs2();

  if(unlikely(perm & ~RT_PERMS)) {
		trap.epc = regs->mepc;
		trap.cause = RISCV_EXCP_SECCELL_ILL_PERM;
		trap.tval = (0 << 8) | (uint8_t)perm;
		return sbi_trap_redirect(regs, &trap);
	} else if (unlikely(!perm)) {
		trap.epc = regs->mepc;
		trap.cause = RISCV_EXCP_SECCELL_ILL_PERM;
		trap.tval = (1 << 8) | (uint8_t)perm;
		return sbi_trap_redirect(regs, &trap);
  }

	ci = sccck(addr, 0);
	/* ChecK: valid address */
	if (unlikely(ci < 0)) {
		trap.epc = regs->mepc;
		trap.cause = RISCV_EXCP_SECCELL_ILL_ADDR;
		trap.tval = addr;
		return sbi_trap_redirect(regs, &trap);
	} else if (unlikely(ci == 0)) { 
		trap.epc = regs->mepc;
		/* Check: Already Valid cell */
	  trap.cause = RISCV_EXCP_SECCELL_INV_CELL_STATE;
		trap.tval = 1;
		return sbi_trap_redirect(regs, &trap);
	}

	*scpa(ci, 0) = RT_D | RT_A | perm | RT_V;
	*scpa(ci, (uint64_t)(-1l)) |= RT_V;

	scca(ci)[1] |= (1ul << 63);
	__asm__ __volatile("sfence.vma");

	regs->mepc += 4;
	return 0;
}

int emulate_scgrant(struct sbi_trap_regs *regs) {
	int64_t ci;
	uint64_t addr, sdtgt;
	uint8_t *ptable, perm, existing_perms;
	uint32_t M;
	struct sbi_trap_info trap;

	addr = get_rs1();
	sdtgt = get_rs2();
	perm = get_imm();
	ci = sccck(addr, 1);
	/* ChecK: valid address */
	if (unlikely(ci < 0)) {
		trap.epc = regs->mepc;
		trap.cause = RISCV_EXCP_SECCELL_ILL_ADDR;
		trap.tval = addr;
		return sbi_trap_redirect(regs, &trap);
	} else if (unlikely(ci == 0)) {
	/* Check: For Valid cell */
		trap.epc = regs->mepc;
		trap.cause = RISCV_EXCP_SECCELL_INV_CELL_STATE;
		trap.tval = 0;
		return sbi_trap_redirect(regs, &trap);
	}

	ptable = (uint8_t *)(uintptr_t)((csr_read(CSR_SATP) & SATP64_PPN) << 12);
	M = ((uint32_t *)ptable)[2];
	if(unlikely((sdtgt == 0) || (sdtgt > M))) {
		trap.epc = regs->mepc;
		trap.cause = RISCV_EXCP_SECCELL_INV_SDID;
		trap.tval = sdtgt;
		return sbi_trap_redirect(regs, &trap);
	}

	if(unlikely(perm & ~RT_PERMS)) {
		trap.epc = regs->mepc;
		trap.cause = RISCV_EXCP_SECCELL_ILL_PERM;
		trap.tval = (0 << 8) | (uint8_t)perm;
		return sbi_trap_redirect(regs, &trap);
  } else if(unlikely((perm & RT_PERMS) == 0)) {
		trap.epc = regs->mepc;
		trap.cause = RISCV_EXCP_SECCELL_ILL_PERM;
		trap.tval = (1 << 8) | (uint8_t)perm;
		return sbi_trap_redirect(regs, &trap);
	}
	existing_perms = *scpa(ci, 0);
	if(unlikely(perm & ~existing_perms)) {
		trap.epc = regs->mepc;
		trap.cause = RISCV_EXCP_SECCELL_ILL_PERM;
		trap.tval = (2 << 8) | (uint8_t)perm;
		return sbi_trap_redirect(regs, &trap);
	}

	*scga(ci, 0) = G(sdtgt, perm);
	__asm__ __volatile("sfence.vma");

	regs->mepc += 4;
	return 0;
}

int emulate_screcv(struct sbi_trap_regs *regs) {
	int64_t ci;
	uint64_t addr, sdsrc, usid;
	uint8_t *ptable, perm, existing_perms;
	uint32_t M, grant;
	struct sbi_trap_info trap;

	addr = get_rs1();
	sdsrc = get_rs2();
	perm = get_imm();

	ci = sccck(addr, 1);
	/* ChecK: valid address */
	if (unlikely(ci < 0)) {
		trap.epc = regs->mepc;
		trap.cause = RISCV_EXCP_SECCELL_ILL_ADDR;
		trap.tval = addr;
		return sbi_trap_redirect(regs, &trap);
	} else if (unlikely(ci == 0)) {
		trap.epc = regs->mepc;
		/* Check: For Valid cell */
		trap.cause = RISCV_EXCP_SECCELL_INV_CELL_STATE;
		trap.tval = 0;
		return sbi_trap_redirect(regs, &trap);
	}

	ptable = (uint8_t *)(uintptr_t)((csr_read(CSR_SATP) & SATP64_PPN) << 12);
	M = ((uint32_t *)ptable)[2];
	if(unlikely((sdsrc == 0) || (sdsrc > M))) {
		trap.epc = regs->mepc;
		trap.cause = RISCV_EXCP_SECCELL_INV_SDID;
		trap.tval = sdsrc;
		return sbi_trap_redirect(regs, &trap);
	}

	if(unlikely(perm & ~RT_PERMS)) {
		trap.epc = regs->mepc;
		trap.cause = RISCV_EXCP_SECCELL_ILL_PERM;
		trap.tval = (0 << 8) | (uint8_t)perm;
		return sbi_trap_redirect(regs, &trap);
  } else if(unlikely((perm & RT_PERMS) == 0)) {
		trap.epc = regs->mepc;
		trap.cause = RISCV_EXCP_SECCELL_ILL_PERM;
		trap.tval = (1 << 8) | (uint8_t)perm;
		return sbi_trap_redirect(regs, &trap);
	}

	grant = *scga(ci, sdsrc);
	existing_perms = *scpa(ci, 0);

	usid = csr_read(CSR_USID);
	if(unlikely((grant >> 4) != usid)){
		trap.epc = regs->mepc;
		// trap.cause;
		// trap.tval;
		return sbi_trap_redirect(regs, &trap);
	}
	if(unlikely(perm & ~(grant & RT_PERMS))) {
		trap.epc = regs->mepc;
		// trap.cause;
		// trap.tval;
		return sbi_trap_redirect(regs, &trap);
	}

	if(perm == (grant & RT_PERMS))
		*scga(ci, sdsrc) = G(SDINV, 0);
	else
		*scga(ci, sdsrc) = G(sdsrc, ((grant & RT_PERMS) & ~perm));
	*scpa(ci, 0) = existing_perms | perm | RT_V;
	__asm__ __volatile("sfence.vma");

	regs->mepc += 4;
	return 0;
}

int emulate_sctfer(struct sbi_trap_regs *regs) {
	uint64_t addr;
	struct sbi_trap_info trap;

	addr = get_rs1();

	emulate_scgrant(regs);

	if(_emulate_scprot(addr, 0, regs, &trap.cause, &trap.tval)){
		trap.epc = regs->mepc;
    return sbi_trap_redirect(regs, &trap);
	}

	__asm__ __volatile("sfence.vma");
	regs->mepc += 4;
	return 0;
}

int emulate_scexcl(struct sbi_trap_regs *regs) {
	uint64_t sd, addr, usid;
	uint32_t M, gperm;
	uint8_t *ptable, perm, existing_perms, pperm;
	int64_t ci;
	struct sbi_trap_info trap;

	addr = get_rs1();
	perm = get_rs2();
	ci = sccck(addr, 1);
	/* ChecK: valid address */
	if (unlikely(ci < 0)) {
		trap.epc = regs->mepc;
		trap.cause = RISCV_EXCP_SECCELL_ILL_ADDR;
		trap.tval = addr;
		return sbi_trap_redirect(regs, &trap);
	} else if (unlikely(ci == 0)) {
	/* Check: For Valid cell */
		trap.epc = regs->mepc;
		trap.cause = RISCV_EXCP_SECCELL_INV_CELL_STATE;
		trap.tval = 0;
		return sbi_trap_redirect(regs, &trap);
	}

	existing_perms = *scpa(ci, 0);
  if(unlikely(perm & ~RT_PERMS)) {
		trap.epc = regs->mepc;
		trap.cause = RISCV_EXCP_SECCELL_ILL_PERM;
		trap.tval = (0 << 8) | (uint8_t)perm;
		return -1;
  } else if(unlikely((perm & RT_PERMS) == 0)) {
		trap.epc = regs->mepc;
		trap.cause = RISCV_EXCP_SECCELL_ILL_PERM;
		trap.tval = (1 << 8) | (uint8_t)perm;
		return sbi_trap_redirect(regs, &trap);
	} else if(unlikely(perm & ~existing_perms)) {
		trap.epc = regs->mepc;
		trap.cause = RISCV_EXCP_SECCELL_ILL_PERM;
		trap.tval = (2 << 8) | (uint8_t)perm;
		return -1;
	}

	ptable = (uint8_t *)(uintptr_t)((csr_read(CSR_SATP) & SATP64_PPN) << 12);
	M = ((uint32_t *)ptable)[2];
	usid = csr_read(CSR_USID);
	for(sd = 1; sd < M; sd++) {
		if(sd != usid) {
			pperm = *scpa(ci, sd);
			gperm = *scga(ci, sd) & 0x0000000F;
			if ((perm | pperm | gperm) == (pperm | gperm))
				break;
		}
	}
	if (sd == M) /* Case: Exclusive */
		set_rd(0);
	else
		set_rd(1);

	regs->mepc += 4;
	return 0;
}
