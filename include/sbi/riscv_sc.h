
#ifndef __RISCV_SECCELLS_H__
#define __RISCV_SECCELLS_H__

#include <sbi/sbi_trap.h>

/* RiscV SecureCells instructions encodings */
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

/* Range table constants */
#define CELL_DESC_SZ  16
#define CELL_PERM_SZ  1
#define RT_V          0x0000000000000001ull // Valid
#define RT_R          0x0000000000000002ull // Read
#define RT_W          0x0000000000000004ull // Write
#define RT_X          0x0000000000000008ull // Execute
#define RT_G          0x0000000000000020ull // Global
#define RT_A          0x0000000000000040ull // Accessed
#define RT_D          0x0000000000000080ull // Dirty
#define RT_PERMS          (RT_R | RT_W | RT_X)

/* List of SecureCells exceptions for scause */
#define RISCV_EXCP_SECCELL_ILL_ADDR         0x18
#define RISCV_EXCP_SECCELL_ILL_PERM         0x19
#define RISCV_EXCP_SECCELL_INV_SDID         0x1a
#define RISCV_EXCP_SECCELL_INV_CELL_STATE   0x1b
#define RISCV_EXCP_SECCELL_ILL_TGT          0x1c

#define CLINES 64
#define G(sdtgt, perm)              ((sdtgt << 4) | perm)
#define SDINV                       (-1)

int emulate_scprot(struct sbi_trap_regs *regs);
int emulate_scinval(struct sbi_trap_regs *regs);
int emulate_screval(struct sbi_trap_regs *regs);
int emulate_scgrant(struct sbi_trap_regs *regs);
int emulate_screcv(struct sbi_trap_regs *regs);
int emulate_sctfer(struct sbi_trap_regs *regs);
int emulate_scexcl(struct sbi_trap_regs *regs);

#endif /* __RISCV_SECCELLS_H__ */