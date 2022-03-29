/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates.
 *
 * Authors:
 *   Anup Patel <anup.patel@wdc.com>
 */

#include <sbi/riscv_asm.h>
#include <sbi/riscv_encoding.h>
#include <sbi/sbi_bitops.h>
#include <sbi/sbi_emulate_csr.h>
#include <sbi/sbi_error.h>
#include <sbi/sbi_illegal_insn.h>
#include <sbi/sbi_pmu.h>
#include <sbi/sbi_trap.h>
#include <sbi/sbi_unpriv.h>

typedef int (*illegal_insn_func)(ulong insn, struct sbi_trap_regs *regs);

static int truly_illegal_insn(ulong insn, struct sbi_trap_regs *regs)
{
	struct sbi_trap_info trap;

	trap.epc = regs->mepc;
	trap.cause = CAUSE_ILLEGAL_INSTRUCTION;
	trap.tval = insn;
	trap.tval2 = 0;
	trap.tinst = 0;

	return sbi_trap_redirect(regs, &trap);
}

static int system_opcode_insn(ulong insn, struct sbi_trap_regs *regs)
{
	int do_write, rs1_num = (insn >> 15) & 0x1f;
	ulong rs1_val = GET_RS1(insn, regs);
	int csr_num   = (u32)insn >> 20;
	ulong csr_val, new_csr_val;

	/* TODO: Ensure that we got CSR read/write instruction */

	if (sbi_emulate_csr_read(csr_num, regs, &csr_val))
		return truly_illegal_insn(insn, regs);

	do_write = rs1_num;
	switch (GET_RM(insn)) {
	case 1:
		new_csr_val = rs1_val;
		do_write    = 1;
		break;
	case 2:
		new_csr_val = csr_val | rs1_val;
		break;
	case 3:
		new_csr_val = csr_val & ~rs1_val;
		break;
	case 5:
		new_csr_val = rs1_num;
		do_write    = 1;
		break;
	case 6:
		new_csr_val = csr_val | rs1_num;
		break;
	case 7:
		new_csr_val = csr_val & ~rs1_num;
		break;
	default:
		return truly_illegal_insn(insn, regs);
	};

	if (do_write && sbi_emulate_csr_write(csr_num, regs, new_csr_val))
		return truly_illegal_insn(insn, regs);

	SET_RD(insn, regs, csr_val);

	regs->mepc += 4;

	return 0;
}

#include <string.h>
#include <inttypes.h>
#define MATCH_PROT 0x300b
#define MASK_PROT  0xfe007fff
#define MATCH_INVAL 0x8000200b
#define MASK_INVAL  0xfff07fff
#define MATCH_REVAL 0x200b
#define MASK_REVAL  0xfe007fff

static int seccell_insn(ulong insn, struct sbi_trap_regs *regs)
{	
	int i;
	struct sbi_trap_info trap;

	trap.epc = regs->mepc;
	trap.tval2 = 0;
	trap.tinst = 0;

	/* Emulating SCProt */
	if((insn & MASK_PROT)  == MATCH_PROT) {
		uint64_t addr_vpn = GET_RS1(insn, regs) >> 12;
		uint64_t perm = GET_RS2(insn, regs);
		uint64_t usid = csr_read(CSR_USID);

		char *ptable = (char *)(uintptr_t)((csr_read(CSR_SATP) & SATP32_PPN) << 12);
		uint32_t T = ((uint32_t *)ptable)[1];
		uint32_t N = ((uint32_t *)ptable)[3];

		char *perms = ptable + (16 * 64 * T) + (usid * 64 * T);
		uint64_t desc[2];
		for(i = 1; i < N; i++) {
			memcpy(desc, ptable + (i * 2 * sizeof(uint64_t)), sizeof(desc));
			uint64_t vpn_start = (desc[0] & ((1ul << 36) - 1));
			uint64_t vpn_end = ((desc[1] & 0xff) << 28) | (desc[0] >> 36);
			if((vpn_start <= addr_vpn) && (addr_vpn <= vpn_end))
				break;
		}

		/* ChecK: valid address */
		if(i == N){
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

		uint8_t existing_perms = *(perms + i);
		if(perm & ~existing_perms)
			return -1;
		*(perms + i) = (existing_perms & (~0b1110ul)) | (perm & 0b1110ul);
		__asm__ __volatile("sfence.vma");
	}
	/* Emulating simplified inval */
	else if ((insn & MASK_INVAL) == MATCH_INVAL) {
		uint64_t addr_vpn = GET_RS1(insn, regs) >> 12;
		char *ptable = (char *)(uintptr_t)((csr_read(CSR_SATP) & SATP32_PPN) << 12);
		uint32_t N = ((uint32_t *)ptable)[3];
		
		uint64_t desc[2];
		for(i = 1; i < N; i++) {
			memcpy(desc, ptable + (i * 2 * sizeof(uint64_t)), sizeof(desc));
			uint64_t vpn_start = (desc[0] & ((1ul << 36) - 1));
			uint64_t vpn_end = ((desc[1] & 0xff) << 28) | (desc[0] >> 36);
			if((vpn_start <= addr_vpn) && (addr_vpn <= vpn_end))
				break;
		}

		/* ChecK: valid address */
		if(i == N)
			return -1;
		/* Check: Already inValid cell */
		if(!(desc[1] & (1ul << 63)))
			return -1;

		desc[1] &= ~(1ul << 63);
		((uint64_t *)(ptable + (i * 2 * sizeof(uint64_t))))[1] = desc[1];
		__asm__ __volatile("sfence.vma");
	} /* Emulating simplified reval */
	else if ((insn & MASK_REVAL) == MATCH_REVAL) {
		uint64_t addr_vpn = GET_RS1(insn, regs) >> 12;
		uint64_t perm = GET_RS2(insn, regs);
		uint64_t usid = csr_read(CSR_USID);

		char *ptable = (char *)(uintptr_t)((csr_read(CSR_SATP) & SATP32_PPN) << 12);
		uint32_t T = ((uint32_t *)ptable)[1];
		uint32_t N = ((uint32_t *)ptable)[3];
		
		uint64_t desc[2];
		for(i = 1; i < N; i++) {
			memcpy(desc, ptable + (i * 2 * sizeof(uint64_t)), sizeof(desc));
			uint64_t vpn_start = (desc[0] & ((1ul << 36) - 1));
			uint64_t vpn_end = ((desc[1] & 0xff) << 28) | (desc[0] >> 36);
			if((vpn_start <= addr_vpn) && (addr_vpn <= vpn_end))
				break;
		}

		/* ChecK: valid address */
		if(i == N)
			return -1;
		/* Check: Already Valid cell */
		if(desc[1] & (1ul << 63))
			return -1;

		desc[1] |= (1ul << 63);

		*(ptable + (16 * 64 * T) + (usid * 64 * T) + i) = 0xc1 | perm;
		((uint64_t *)(ptable + (i * 2 * sizeof(uint64_t))))[1] = desc[1];
		__asm__ __volatile("sfence.vma");
	} else
		return -1;

	regs->mepc += 4;
	return 0;
}

static illegal_insn_func illegal_insn_table[32] = {
	truly_illegal_insn, /* 0 */
	truly_illegal_insn, /* 1 */
	seccell_insn,       /* 2 */
	truly_illegal_insn, /* 3 */
	truly_illegal_insn, /* 4 */
	truly_illegal_insn, /* 5 */
	truly_illegal_insn, /* 6 */
	truly_illegal_insn, /* 7 */
	truly_illegal_insn, /* 8 */
	truly_illegal_insn, /* 9 */
	truly_illegal_insn, /* 10 */
	truly_illegal_insn, /* 11 */
	truly_illegal_insn, /* 12 */
	truly_illegal_insn, /* 13 */
	truly_illegal_insn, /* 14 */
	truly_illegal_insn, /* 15 */
	truly_illegal_insn, /* 16 */
	truly_illegal_insn, /* 17 */
	truly_illegal_insn, /* 18 */
	truly_illegal_insn, /* 19 */
	truly_illegal_insn, /* 20 */
	truly_illegal_insn, /* 21 */
	truly_illegal_insn, /* 22 */
	truly_illegal_insn, /* 23 */
	truly_illegal_insn, /* 24 */
	truly_illegal_insn, /* 25 */
	truly_illegal_insn, /* 26 */
	truly_illegal_insn, /* 27 */
	system_opcode_insn, /* 28 */
	truly_illegal_insn, /* 29 */
	truly_illegal_insn, /* 30 */
	truly_illegal_insn  /* 31 */
};

int sbi_illegal_insn_handler(ulong insn, struct sbi_trap_regs *regs)
{
	struct sbi_trap_info uptrap;

	/*
	 * We only deal with 32-bit (or longer) illegal instructions. If we
	 * see instruction is zero OR instruction is 16-bit then we fetch and
	 * check the instruction encoding using unprivilege access.
	 *
	 * The program counter (PC) in RISC-V world is always 2-byte aligned
	 * so handling only 32-bit (or longer) illegal instructions also help
	 * the case where MTVAL CSR contains instruction address for illegal
	 * instruction trap.
	 */

	sbi_pmu_ctr_incr_fw(SBI_PMU_FW_ILLEGAL_INSN);
	if (unlikely((insn & 3) != 3)) {
		insn = sbi_get_insn(regs->mepc, &uptrap);
		if (uptrap.cause) {
			uptrap.epc = regs->mepc;
			return sbi_trap_redirect(regs, &uptrap);
		}
		if ((insn & 3) != 3)
			return truly_illegal_insn(insn, regs);
	}

	return illegal_insn_table[(insn & 0x7c) >> 2](insn, regs);
}
