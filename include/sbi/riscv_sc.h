
#ifndef __RISCV_SECCELLS_H__
#define __RISCV_SECCELLS_H__

#include <sbi/sbi_trap.h>

#define MATCH_PROT 0x300b
#define MASK_PROT  0xfe007fff
#define MATCH_INVAL 0x8000200b
#define MASK_INVAL  0xfff07fff
#define MATCH_REVAL 0x200b
#define MASK_REVAL  0xfe007fff
#define MATCH_GRANT 0x400b
#define MASK_GRANT  0x707f
#define MATCH_TFER 0x500b
#define MASK_TFER  0x707f
#define MATCH_RECV 0x600b
#define MASK_RECV  0x707f
#define MATCH_EXCL 0x700b
#define MASK_EXCL  0xfe00707f

#define CLINES 64
#define PT(ptable, T, sd, ci) 	    (ptable + (16 * T * CLINES) + (sd * T * CLINES) + ci)
#define GT(ptable, R, T, sd, ci)    (ptable + (16 * T * CLINES) + (R * T * CLINES) + (usid * 4 * T * CLINES) + (4 * ci))
#define G(sdtgt, perm)              ((sdtgt << 3) | perm)

int emulate_scprot(ulong insn, struct sbi_trap_regs *regs);
int emulate_scinval(ulong insn, struct sbi_trap_regs *regs);
int emulate_screval(ulong insn, struct sbi_trap_regs *regs);
int emulate_scgrant(ulong insn, struct sbi_trap_regs *regs);
int emulate_screcv(ulong insn, struct sbi_trap_regs *regs);
int emulate_sctfer(ulong insn, struct sbi_trap_regs *regs);
int emulate_scexcl(ulong insn, struct sbi_trap_regs *regs);

#endif /* __RISCV_SECCELLS_H__ */