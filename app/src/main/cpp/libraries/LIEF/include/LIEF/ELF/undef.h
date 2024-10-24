/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef LIEF_ELF_UNDEF_H
#define LIEF_ELF_UNDEF_H

#ifdef PT_LOAD
#pragma message("LIEF will disable #define enums. Please use LIEF_ELF_XXXX or LIEF::ELF::XXXX instead!")
#endif

#undef EI_MAG0
#undef EI_MAG1
#undef EI_MAG2
#undef EI_MAG3
#undef EI_CLASS
#undef EI_DATA
#undef EI_VERSION
#undef EI_OSABI
#undef EI_ABIVERSION
#undef EI_PAD
#undef EI_NIDENT


#undef ET_NONE
#undef ET_REL
#undef ET_EXEC
#undef ET_DYN
#undef ET_CORE
#undef ET_LOPROC
#undef ET_HIPROC


#undef EV_NONE
#undef EV_CURRENT



#undef EM_NONE
#undef EM_M32
#undef EM_SPARC
#undef EM_386
#undef EM_68K
#undef EM_88K
#undef EM_IAMCU
#undef EM_860
#undef EM_MIPS
#undef EM_S370
#undef EM_MIPS_RS3_LE
#undef EM_PARISC
#undef EM_VPP500
#undef EM_SPARC32PLUS
#undef EM_960
#undef EM_PPC
#undef EM_PPC64
#undef EM_S390
#undef EM_SPU
#undef EM_V800
#undef EM_FR20
#undef EM_RH32
#undef EM_RCE
#undef EM_ARM
#undef EM_ALPHA
#undef EM_SH
#undef EM_SPARCV9
#undef EM_TRICORE
#undef EM_ARC
#undef EM_H8_300
#undef EM_H8_300H
#undef EM_H8S
#undef EM_H8_500
#undef EM_IA_64
#undef EM_MIPS_X
#undef EM_COLDFIRE
#undef EM_68HC12
#undef EM_MMA
#undef EM_PCP
#undef EM_NCPU
#undef EM_NDR1
#undef EM_STARCORE
#undef EM_ME16
#undef EM_ST100
#undef EM_TINYJ
#undef EM_X86_64
#undef EM_PDSP
#undef EM_PDP10
#undef EM_PDP11
#undef EM_FX66
#undef EM_ST9PLUS
#undef EM_ST7
#undef EM_68HC16
#undef EM_68HC11
#undef EM_68HC08
#undef EM_68HC05
#undef EM_SVX
#undef EM_ST19
#undef EM_VAX
#undef EM_CRIS
#undef EM_JAVELIN
#undef EM_FIREPATH
#undef EM_ZSP
#undef EM_MMIX
#undef EM_HUANY
#undef EM_PRISM
#undef EM_AVR
#undef EM_FR30
#undef EM_D10V
#undef EM_D30V
#undef EM_V850
#undef EM_M32R
#undef EM_MN10300
#undef EM_MN10200
#undef EM_PJ
#undef EM_OPENRISC
#undef EM_ARC_COMPACT
#undef EM_XTENSA
#undef EM_VIDEOCORE
#undef EM_TMM_GPP
#undef EM_NS32K
#undef EM_TPC
#undef EM_SNP1K
#undef EM_ST200
#undef EM_IP2K
#undef EM_MAX
#undef EM_CR
#undef EM_F2MC16
#undef EM_MSP430
#undef EM_BLACKFIN
#undef EM_SE_C33
#undef EM_SEP
#undef EM_ARCA
#undef EM_UNICORE
#undef EM_EXCESS
#undef EM_DXP
#undef EM_ALTERA_NIOS2
#undef EM_CRX
#undef EM_XGATE
#undef EM_C166
#undef EM_M16C
#undef EM_DSPIC30F

#undef EM_CE
#undef EM_M32C
#undef EM_TSK3000
#undef EM_RS08
#undef EM_SHARC

#undef EM_ECOG2
#undef EM_SCORE7
#undef EM_DSP24
#undef EM_VIDEOCORE3
#undef EM_LATTICEMICO32
#undef EM_SE_C17
#undef EM_TI_C6000
#undef EM_TI_C2000
#undef EM_TI_C5500
#undef EM_MMDSP_PLUS
#undef EM_CYPRESS_M8C
#undef EM_R32C
#undef EM_TRIMEDIA
#undef EM_HEXAGON
#undef EM_8051
#undef EM_STXP7X

#undef EM_NDS32

#undef EM_ECOG1
#undef EM_ECOG1X
#undef EM_MAXQ30
#undef EM_XIMO16
#undef EM_MANIK
#undef EM_CRAYNV2
#undef EM_RX
#undef EM_METAG

#undef EM_MCST_ELBRUS
#undef EM_ECOG16
#undef EM_CR16

#undef EM_ETPU
#undef EM_SLE9X
#undef EM_L10M
#undef EM_K10M
#undef EM_AARCH64
#undef EM_AVR32
#undef EM_STM8
#undef EM_TILE64
#undef EM_TILEPRO
#undef EM_CUDA
#undef EM_TILEGX
#undef EM_CLOUDSHIELD
#undef EM_COREA_1ST
#undef EM_COREA_2ND
#undef EM_ARC_COMPACT2
#undef EM_OPEN8
#undef EM_RL78
#undef EM_VIDEOCORE5
#undef EM_78KOR
#undef EM_56800EX
#undef EM_BA1
#undef EM_BA2
#undef EM_XCORE
#undef EM_MCHP_PIC
#undef EM_INTEL205
#undef EM_INTEL206
#undef EM_INTEL207
#undef EM_INTEL208
#undef EM_INTEL209
#undef EM_KM32
#undef EM_KMX32
#undef EM_KMX16
#undef EM_KMX8
#undef EM_KVARC
#undef EM_CDP
#undef EM_COGE
#undef EM_COOL
#undef EM_NORC
#undef EM_CSR_KALIMBA
#undef EM_AMDGPU
#undef EM_RISCV
#undef EM_BPF
#undef EM_LOONGARCH


#undef ELFCLASSNONE
#undef ELFCLASS32
#undef ELFCLASS64

#undef ELFDATANONE
#undef ELFDATA2LSB
#undef ELFDATA2MSB

#undef ELFOSABI_SYSTEMV
#undef ELFOSABI_HPUX
#undef ELFOSABI_NETBSD
#undef ELFOSABI_GNU
#undef ELFOSABI_LINUX
#undef ELFOSABI_HURD
#undef ELFOSABI_SOLARIS
#undef ELFOSABI_AIX
#undef ELFOSABI_IRIX
#undef ELFOSABI_FREEBSD
#undef ELFOSABI_TRU64
#undef ELFOSABI_MODESTO
#undef ELFOSABI_OPENBSD
#undef ELFOSABI_OPENVMS
#undef ELFOSABI_NSK
#undef ELFOSABI_AROS
#undef ELFOSABI_FENIXOS
#undef ELFOSABI_CLOUDABI
#undef ELFOSABI_C6000_ELFABI
#undef ELFOSABI_AMDGPU_HSA
#undef ELFOSABI_C6000_LINUX
#undef ELFOSABI_ARM
#undef ELFOSABI_STANDALONE

#undef EF_PPC64_ABI
#undef EF_ARM_SOFT_FLOAT
#undef EF_ARM_VFP_FLOAT
#undef EF_ARM_EABI_UNKNOWN
#undef EF_ARM_EABI_VER1
#undef EF_ARM_EABI_VER2
#undef EF_ARM_EABI_VER3
#undef EF_ARM_EABI_VER4
#undef EF_ARM_EABI_VER5
#undef EF_ARM_EABIMASK

#undef EF_MIPS_NOREORDER
#undef EF_MIPS_PIC
#undef EF_MIPS_CPIC
#undef EF_MIPS_ABI2
#undef EF_MIPS_32BITMODE

#undef EF_MIPS_FP64

#undef EF_MIPS_NAN2008


#undef EF_MIPS_ABI_O32
#undef EF_MIPS_ABI_O64
#undef EF_MIPS_ABI_EABI32
#undef EF_MIPS_ABI_EABI64
#undef EF_MIPS_ABI


#undef EF_MIPS_MACH_3900
#undef EF_MIPS_MACH_4010
#undef EF_MIPS_MACH_4100
#undef EF_MIPS_MACH_4650
#undef EF_MIPS_MACH_4120
#undef EF_MIPS_MACH_4111
#undef EF_MIPS_MACH_SB1
#undef EF_MIPS_MACH_OCTEON
#undef EF_MIPS_MACH_XLR
#undef EF_MIPS_MACH_OCTEON2
#undef EF_MIPS_MACH_OCTEON3
#undef EF_MIPS_MACH_5400
#undef EF_MIPS_MACH_5900
#undef EF_MIPS_MACH_5500
#undef EF_MIPS_MACH_9000
#undef EF_MIPS_MACH_LS2E
#undef EF_MIPS_MACH_LS2F
#undef EF_MIPS_MACH_LS3A
#undef EF_MIPS_MACH


#undef EF_MIPS_MICROMIPS
#undef EF_MIPS_ARCH_ASE_M16
#undef EF_MIPS_ARCH_ASE_MDMX
#undef EF_MIPS_ARCH_ASE


#undef EF_MIPS_ARCH_1
#undef EF_MIPS_ARCH_2
#undef EF_MIPS_ARCH_3
#undef EF_MIPS_ARCH_4
#undef EF_MIPS_ARCH_5
#undef EF_MIPS_ARCH_32
#undef EF_MIPS_ARCH_64
#undef EF_MIPS_ARCH_32R2
#undef EF_MIPS_ARCH_64R2
#undef EF_MIPS_ARCH_32R6
#undef EF_MIPS_ARCH_64R6
#undef EF_MIPS_ARCH


#undef EF_HEXAGON_MACH_V2
#undef EF_HEXAGON_MACH_V3
#undef EF_HEXAGON_MACH_V4
#undef EF_HEXAGON_MACH_V5

#undef EF_HEXAGON_ISA_MACH
#undef EF_HEXAGON_ISA_V2
#undef EF_HEXAGON_ISA_V3
#undef EF_HEXAGON_ISA_V4
#undef EF_HEXAGON_ISA_V5


#undef EF_LOONGARCH_ABI_SOFT_FLOAT
#undef EF_LOONGARCH_ABI_SINGLE_FLOAT
#undef EF_LOONGARCH_ABI_DOUBLE_FLOAT


#undef SHN_UNDEF
#undef SHN_LORESERVE
#undef SHN_LOPROC
#undef SHN_HIPROC
#undef SHN_LOOS
#undef SHN_HIOS
#undef SHN_ABS
#undef SHN_COMMON
#undef SHN_XINDEX
#undef SHN_HIRESERVE


#undef SHT_NULL
#undef SHT_PROGBITS
#undef SHT_SYMTAB
#undef SHT_STRTAB
#undef SHT_RELA
#undef SHT_HASH
#undef SHT_DYNAMIC
#undef SHT_NOTE
#undef SHT_NOBITS
#undef SHT_REL
#undef SHT_SHLIB
#undef SHT_DYNSYM
#undef SHT_INIT_ARRAY
#undef SHT_FINI_ARRAY
#undef SHT_PREINIT_ARRAY
#undef SHT_GROUP
#undef SHT_SYMTAB_SHNDX
#undef SHT_LOOS
#undef SHT_GNU_ATTRIBUTES
#undef SHT_GNU_HASH
#undef SHT_GNU_verdef
#undef SHT_GNU_verneed
#undef SHT_GNU_versym
#undef SHT_HIOS
#undef SHT_LOPROC
#undef SHT_ARM_EXIDX
#undef SHT_ARM_PREEMPTMAP
#undef SHT_ARM_ATTRIBUTES
#undef SHT_ARM_DEBUGOVERLAY
#undef SHT_ARM_OVERLAYSECTION
#undef SHT_HEX_ORDERED

#undef SHT_X86_64_UNWIND
#undef SHT_MIPS_REGINFO
#undef SHT_MIPS_OPTIONS
#undef SHT_MIPS_ABIFLAGS

#undef SHT_HIPROC
#undef SHT_LOUSER
#undef SHT_HIUSER

#undef SHT_ANDROID_REL
#undef SHT_ANDROID_RELA
#undef SHT_LLVM_ADDRSIG
#undef SHT_RELR

#undef SHF_NONE
#undef SHF_WRITE
#undef SHF_ALLOC
#undef SHF_EXECINSTR
#undef SHF_MERGE
#undef SHF_STRINGS
#undef SHF_INFO_LINK
#undef SHF_LINK_ORDER
#undef SHF_OS_NONCONFORMING
#undef SHF_GROUP
#undef SHF_TLS
#undef SHF_EXCLUDE
#undef XCORE_SHF_CP_SECTION
#undef XCORE_SHF_DP_SECTION
#undef SHF_MASKOS
#undef SHF_MASKPROC
#undef SHF_X86_64_LARGE
#undef SHF_HEX_GPREL
#undef SHF_MIPS_NODUPES

#undef SHF_MIPS_NAMES
#undef SHF_MIPS_LOCAL
#undef SHF_MIPS_NOSTRIP
#undef SHF_MIPS_GPREL
#undef SHF_MIPS_MERGE
#undef SHF_MIPS_ADDR
#undef SHF_MIPS_STRING

#undef STB_LOCAL
#undef STB_GLOBAL
#undef STB_WEAK
#undef STB_GNU_UNIQUE
#undef STB_LOOS
#undef STB_HIOS
#undef STB_LOPROC
#undef STB_HIPROC

#undef STT_NOTYPE
#undef STT_OBJECT
#undef STT_FUNC
#undef STT_SECTION
#undef STT_FILE
#undef STT_COMMON
#undef STT_TLS
#undef STT_GNU_IFUNC
#undef STT_LOOS
#undef STT_HIOS
#undef STT_LOPROC
#undef STT_HIPROC

#undef STV_DEFAULT
#undef STV_INTERNAL
#undef STV_HIDDEN
#undef STV_PROTECTED

#undef PT_NULL
#undef PT_LOAD
#undef PT_DYNAMIC
#undef PT_INTERP
#undef PT_NOTE
#undef PT_SHLIB
#undef PT_PHDR
#undef PT_TLS
#undef PT_LOOS
#undef PT_HIOS
#undef PT_LOPROC
#undef PT_HIPROC

#undef PT_GNU_EH_FRAME
#undef PT_SUNW_EH_FRAME
#undef PT_SUNW_UNWIND

#undef PT_GNU_STACK
#undef PT_GNU_RELRO

#undef PT_ARM_ARCHEXT

#undef PT_ARM_EXIDX
#undef PT_ARM_UNWIND

#undef PT_MIPS_REGINFO
#undef PT_MIPS_RTPROC
#undef PT_MIPS_OPTIONS
#undef PT_MIPS_ABIFLAGS


#undef PF_NONE
#undef PF_X
#undef PF_W
#undef PF_R
#undef PF_MASKOS
#undef PF_MASKPROC

#undef DT_NULL
#undef DT_NEEDED
#undef DT_PLTRELSZ
#undef DT_PLTGOT
#undef DT_HASH
#undef DT_STRTAB
#undef DT_SYMTAB
#undef DT_RELA
#undef DT_RELASZ
#undef DT_RELAENT
#undef DT_STRSZ
#undef DT_SYMENT
#undef DT_INIT
#undef DT_FINI
#undef DT_SONAME
#undef DT_RPATH
#undef DT_SYMBOLIC
#undef DT_REL
#undef DT_RELSZ
#undef DT_RELENT
#undef DT_PLTREL
#undef DT_DEBUG
#undef DT_TEXTREL
#undef DT_JMPREL
#undef DT_BIND_NOW
#undef DT_INIT_ARRAY
#undef DT_FINI_ARRAY
#undef DT_INIT_ARRAYSZ
#undef DT_FINI_ARRAYSZ
#undef DT_RUNPATH
#undef DT_FLAGS
#undef DT_ENCODING

#undef DT_PREINIT_ARRAY
#undef DT_PREINIT_ARRAYSZ

#undef DT_LOOS
#undef DT_HIOS
#undef DT_LOPROC
#undef DT_HIPROC

#undef DT_GNU_HASH
#undef DT_RELACOUNT
#undef DT_RELCOUNT

#undef DT_FLAGS_1
#undef DT_VERSYM
#undef DT_VERDEF
#undef DT_VERDEFNUM
#undef DT_VERNEED
#undef DT_VERNEEDNUM

#undef DT_MIPS_RLD_VERSION
#undef DT_MIPS_TIME_STAMP
#undef DT_MIPS_ICHECKSUM
#undef DT_MIPS_IVERSION
#undef DT_MIPS_FLAGS
#undef DT_MIPS_BASE_ADDRESS
#undef DT_MIPS_MSYM
#undef DT_MIPS_CONFLICT
#undef DT_MIPS_LIBLIST
#undef DT_MIPS_LOCAL_GOTNO
#undef DT_MIPS_CONFLICTNO
#undef DT_MIPS_LIBLISTNO
#undef DT_MIPS_SYMTABNO
#undef DT_MIPS_UNREFEXTNO
#undef DT_MIPS_GOTSYM
#undef DT_MIPS_HIPAGENO
#undef DT_MIPS_RLD_MAP
#undef DT_MIPS_DELTA_CLASS
#undef DT_MIPS_DELTA_CLASS_NO
#undef DT_MIPS_DELTA_INSTANCE
#undef DT_MIPS_DELTA_INSTANCE_NO
#undef DT_MIPS_DELTA_RELOC
#undef DT_MIPS_DELTA_RELOC_NO
#undef DT_MIPS_DELTA_SYM
#undef DT_MIPS_DELTA_SYM_NO
#undef DT_MIPS_DELTA_CLASSSYM
#undef DT_MIPS_DELTA_CLASSSYM_NO
#undef DT_MIPS_CXX_FLAGS
#undef DT_MIPS_PIXIE_INIT
#undef DT_MIPS_SYMBOL_LIB
#undef DT_MIPS_LOCALPAGE_GOTIDX
#undef DT_MIPS_LOCAL_GOTIDX
#undef DT_MIPS_HIDDEN_GOTIDX
#undef DT_MIPS_PROTECTED_GOTIDX
#undef DT_MIPS_OPTIONS
#undef DT_MIPS_INTERFACE
#undef DT_MIPS_DYNSTR_ALIGN
#undef DT_MIPS_INTERFACE_SIZE
#undef DT_MIPS_RLD_TEXT_RESOLVE_ADDR
#undef DT_MIPS_PERF_SUFFIX
#undef DT_MIPS_COMPACT_SIZE
#undef DT_MIPS_GP_VALUE
#undef DT_MIPS_AUX_DYNAMIC
#undef DT_MIPS_PLTGOT
#undef DT_MIPS_RWPLT

#undef DT_ANDROID_REL_OFFSET
#undef DT_ANDROID_REL_SIZE
#undef DT_ANDROID_REL
#undef DT_ANDROID_RELSZ
#undef DT_ANDROID_RELA
#undef DT_ANDROID_RELASZ
#undef DT_RELR
#undef DT_RELRSZ
#undef DT_RELRENT
#undef DT_RELRCOUNT

#undef DF_ORIGIN
#undef DF_SYMBOLIC
#undef DF_TEXTREL
#undef DF_BIND_NOW
#undef DF_STATIC_TLS

#undef DF_1_NOW
#undef DF_1_GLOBAL
#undef DF_1_GROUP
#undef DF_1_NODELETE
#undef DF_1_LOADFLTR
#undef DF_1_INITFIRST
#undef DF_1_NOOPEN
#undef DF_1_ORIGIN
#undef DF_1_DIRECT
#undef DF_1_TRANS
#undef DF_1_INTERPOSE
#undef DF_1_NODEFLIB
#undef DF_1_NODUMP
#undef DF_1_CONFALT
#undef DF_1_ENDFILTEE
#undef DF_1_DISPRELDNE
#undef DF_1_DISPRELPND
#undef DF_1_NODIRECT
#undef DF_1_IGNMULDEF
#undef DF_1_NOKSYMS
#undef DF_1_NOHDR
#undef DF_1_EDITED
#undef DF_1_NORELOC
#undef DF_1_SYMINTPOSE
#undef DF_1_GLOBAUDIT
#undef DF_1_SINGLETON
#undef DF_1_PIE

#undef RHF_NONE
#undef RHF_QUICKSTART
#undef RHF_NOTPOT
#undef RHS_NO_LIBRARY_REPLACEMENT
#undef RHF_NO_MOVE
#undef RHF_SGI_ONLY
#undef RHF_GUARANTEE_INIT
#undef RHF_DELTA_C_PLUS_PLUS
#undef RHF_GUARANTEE_START_INIT
#undef RHF_PIXIE
#undef RHF_DEFAULT_DELAY_LOAD
#undef RHF_REQUICKSTART
#undef RHF_REQUICKSTARTED
#undef RHF_CORD
#undef RHF_NO_UNRES_UNDEF
#undef RHF_RLD_ORDER_SAFE

#undef VER_DEF_NONE
#undef VER_DEF_CURRENT

#undef VER_FLG_BASE
#undef VER_FLG_WEAK
#undef VER_FLG_INFO

#undef VER_NDX_LOCAL
#undef VER_NDX_GLOBAL
#undef VERSYM_VERSION
#undef VERSYM_HIDDEN

#undef VER_NEED_NONE
#undef VER_NEED_CURRENT
#undef COUNT_AUTO
#undef COUNT_SECTION
#undef COUNT_HASH
#undef COUNT_RELOCATIONS

#undef NT_ARM_VFP
#undef NT_ARM_TLS
#undef NT_ARM_HW_BREAK
#undef NT_ARM_HW_WATCH
#undef NT_ARM_SYSTEM_CALL
#undef NT_ARM_SVE

#undef NT_386_TLS
#undef NT_386_IOPERM

#undef NT_UNKNOWN
#undef NT_GNU_ABI_TAG
#undef NT_GNU_HWCAP
#undef NT_GNU_BUILD_ID
#undef NT_GNU_GOLD_VERSION
#undef NT_GNU_BUILD_ATTRIBUTE_OPEN
#undef NT_GNU_BUILD_ATTRIBUTE_FUNC
#undef NT_PRSTATUS
#undef NT_PRFPREG
#undef NT_PRPSINFO
#undef NT_TASKSTRUCT
#undef NT_AUXV
#undef NT_SIGINFO
#undef NT_FILE
#undef NT_PRXFPREG

#undef ELF_NOTE_UNKNOWN
#undef ELF_NOTE_OS_LINUX
#undef ELF_NOTE_OS_GNU
#undef ELF_NOTE_OS_SOLARIS2
#undef ELF_NOTE_OS_FREEBSD
#undef ELF_NOTE_OS_NETBSD
#undef ELF_NOTE_OS_SYLLABLE


#undef RELOC_PURPOSE_NONE
#undef RELOC_PURPOSE_PLTGOT
#undef RELOC_PURPOSE_DYNAMIC
#undef RELOC_PURPOSE_OBJECT

#undef R_AARCH64_NONE

#undef R_AARCH64_ABS64
#undef R_AARCH64_ABS32
#undef R_AARCH64_ABS16
#undef R_AARCH64_PREL64
#undef R_AARCH64_PREL32
#undef R_AARCH64_PREL16

#undef R_AARCH64_MOVW_UABS_G0
#undef R_AARCH64_MOVW_UABS_G0_NC
#undef R_AARCH64_MOVW_UABS_G1
#undef R_AARCH64_MOVW_UABS_G1_NC
#undef R_AARCH64_MOVW_UABS_G2
#undef R_AARCH64_MOVW_UABS_G2_NC
#undef R_AARCH64_MOVW_UABS_G3
#undef R_AARCH64_MOVW_SABS_G0
#undef R_AARCH64_MOVW_SABS_G1
#undef R_AARCH64_MOVW_SABS_G2

#undef R_AARCH64_LD_PREL_LO19
#undef R_AARCH64_ADR_PREL_LO21
#undef R_AARCH64_ADR_PREL_PG_HI21
#undef R_AARCH64_ADR_PREL_PG_HI21_NC
#undef R_AARCH64_ADD_ABS_LO12_NC
#undef R_AARCH64_LDST8_ABS_LO12_NC

#undef R_AARCH64_TSTBR14
#undef R_AARCH64_CONDBR19
#undef R_AARCH64_JUMP26
#undef R_AARCH64_CALL26

#undef R_AARCH64_LDST16_ABS_LO12_NC
#undef R_AARCH64_LDST32_ABS_LO12_NC
#undef R_AARCH64_LDST64_ABS_LO12_NC

#undef R_AARCH64_MOVW_PREL_G0
#undef R_AARCH64_MOVW_PREL_G0_NC
#undef R_AARCH64_MOVW_PREL_G1
#undef R_AARCH64_MOVW_PREL_G1_NC
#undef R_AARCH64_MOVW_PREL_G2
#undef R_AARCH64_MOVW_PREL_G2_NC
#undef R_AARCH64_MOVW_PREL_G3

#undef R_AARCH64_LDST128_ABS_LO12_NC

#undef R_AARCH64_MOVW_GOTOFF_G0
#undef R_AARCH64_MOVW_GOTOFF_G0_NC
#undef R_AARCH64_MOVW_GOTOFF_G1
#undef R_AARCH64_MOVW_GOTOFF_G1_NC
#undef R_AARCH64_MOVW_GOTOFF_G2
#undef R_AARCH64_MOVW_GOTOFF_G2_NC
#undef R_AARCH64_MOVW_GOTOFF_G3

#undef R_AARCH64_GOTREL64
#undef R_AARCH64_GOTREL32

#undef R_AARCH64_GOT_LD_PREL19
#undef R_AARCH64_LD64_GOTOFF_LO15
#undef R_AARCH64_ADR_GOT_PAGE
#undef R_AARCH64_LD64_GOT_LO12_NC
#undef R_AARCH64_LD64_GOTPAGE_LO15

#undef R_AARCH64_TLSGD_ADR_PREL21
#undef R_AARCH64_TLSGD_ADR_PAGE21
#undef R_AARCH64_TLSGD_ADD_LO12_NC
#undef R_AARCH64_TLSGD_MOVW_G1
#undef R_AARCH64_TLSGD_MOVW_G0_NC

#undef R_AARCH64_TLSLD_ADR_PREL21
#undef R_AARCH64_TLSLD_ADR_PAGE21
#undef R_AARCH64_TLSLD_ADD_LO12_NC
#undef R_AARCH64_TLSLD_MOVW_G1
#undef R_AARCH64_TLSLD_MOVW_G0_NC
#undef R_AARCH64_TLSLD_LD_PREL19
#undef R_AARCH64_TLSLD_MOVW_DTPREL_G2
#undef R_AARCH64_TLSLD_MOVW_DTPREL_G1
#undef R_AARCH64_TLSLD_MOVW_DTPREL_G1_NC
#undef R_AARCH64_TLSLD_MOVW_DTPREL_G0
#undef R_AARCH64_TLSLD_MOVW_DTPREL_G0_NC
#undef R_AARCH64_TLSLD_ADD_DTPREL_HI12
#undef R_AARCH64_TLSLD_ADD_DTPREL_LO12
#undef R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC
#undef R_AARCH64_TLSLD_LDST8_DTPREL_LO12
#undef R_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC
#undef R_AARCH64_TLSLD_LDST16_DTPREL_LO12
#undef R_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC
#undef R_AARCH64_TLSLD_LDST32_DTPREL_LO12
#undef R_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC
#undef R_AARCH64_TLSLD_LDST64_DTPREL_LO12
#undef R_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC

#undef R_AARCH64_TLSIE_MOVW_GOTTPREL_G1
#undef R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC
#undef R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21
#undef R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC
#undef R_AARCH64_TLSIE_LD_GOTTPREL_PREL19

#undef R_AARCH64_TLSLE_MOVW_TPREL_G2
#undef R_AARCH64_TLSLE_MOVW_TPREL_G1
#undef R_AARCH64_TLSLE_MOVW_TPREL_G1_NC
#undef R_AARCH64_TLSLE_MOVW_TPREL_G0
#undef R_AARCH64_TLSLE_MOVW_TPREL_G0_NC
#undef R_AARCH64_TLSLE_ADD_TPREL_HI12
#undef R_AARCH64_TLSLE_ADD_TPREL_LO12
#undef R_AARCH64_TLSLE_ADD_TPREL_LO12_NC
#undef R_AARCH64_TLSLE_LDST8_TPREL_LO12
#undef R_AARCH64_TLSLE_LDST8_TPREL_LO12_NC
#undef R_AARCH64_TLSLE_LDST16_TPREL_LO12
#undef R_AARCH64_TLSLE_LDST16_TPREL_LO12_NC
#undef R_AARCH64_TLSLE_LDST32_TPREL_LO12
#undef R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC
#undef R_AARCH64_TLSLE_LDST64_TPREL_LO12
#undef R_AARCH64_TLSLE_LDST64_TPREL_LO12_NC

#undef R_AARCH64_TLSDESC_LD_PREL19
#undef R_AARCH64_TLSDESC_ADR_PREL21
#undef R_AARCH64_TLSDESC_ADR_PAGE21
#undef R_AARCH64_TLSDESC_LD64_LO12_NC
#undef R_AARCH64_TLSDESC_ADD_LO12_NC
#undef R_AARCH64_TLSDESC_OFF_G1
#undef R_AARCH64_TLSDESC_OFF_G0_NC
#undef R_AARCH64_TLSDESC_LDR
#undef R_AARCH64_TLSDESC_ADD
#undef R_AARCH64_TLSDESC_CALL

#undef R_AARCH64_TLSLE_LDST128_TPREL_LO12
#undef R_AARCH64_TLSLE_LDST128_TPREL_LO12_NC

#undef R_AARCH64_TLSLD_LDST128_DTPREL_LO12
#undef R_AARCH64_TLSLD_LDST128_DTPREL_LO12_NC

#undef R_AARCH64_COPY
#undef R_AARCH64_GLOB_DAT
#undef R_AARCH64_JUMP_SLOT
#undef R_AARCH64_RELATIVE
#undef R_AARCH64_TLS_DTPREL64
#undef R_AARCH64_TLS_DTPMOD64
#undef R_AARCH64_TLS_TPREL64
#undef R_AARCH64_TLSDESC
#undef R_AARCH64_IRELATIVE

#undef R_ARM_NONE
#undef R_ARM_PC24
#undef R_ARM_ABS32
#undef R_ARM_REL32
#undef R_ARM_LDR_PC_G0
#undef R_ARM_ABS16
#undef R_ARM_ABS12
#undef R_ARM_THM_ABS5
#undef R_ARM_ABS8
#undef R_ARM_SBREL32
#undef R_ARM_THM_CALL
#undef R_ARM_THM_PC8
#undef R_ARM_BREL_ADJ
#undef R_ARM_TLS_DESC
#undef R_ARM_THM_SWI8
#undef R_ARM_XPC25
#undef R_ARM_THM_XPC22
#undef R_ARM_TLS_DTPMOD32
#undef R_ARM_TLS_DTPOFF32
#undef R_ARM_TLS_TPOFF32
#undef R_ARM_COPY
#undef R_ARM_GLOB_DAT
#undef R_ARM_JUMP_SLOT
#undef R_ARM_RELATIVE
#undef R_ARM_GOTOFF32
#undef R_ARM_BASE_PREL
#undef R_ARM_GOT_BREL
#undef R_ARM_PLT32
#undef R_ARM_CALL
#undef R_ARM_JUMP24
#undef R_ARM_THM_JUMP24
#undef R_ARM_BASE_ABS
#undef R_ARM_ALU_PCREL_7_0
#undef R_ARM_ALU_PCREL_15_8
#undef R_ARM_ALU_PCREL_23_15
#undef R_ARM_LDR_SBREL_11_0_NC
#undef R_ARM_ALU_SBREL_19_12_NC
#undef R_ARM_ALU_SBREL_27_20_CK
#undef R_ARM_TARGET1
#undef R_ARM_SBREL31
#undef R_ARM_V4BX
#undef R_ARM_TARGET2
#undef R_ARM_PREL31
#undef R_ARM_MOVW_ABS_NC
#undef R_ARM_MOVT_ABS
#undef R_ARM_MOVW_PREL_NC
#undef R_ARM_MOVT_PREL
#undef R_ARM_THM_MOVW_ABS_NC
#undef R_ARM_THM_MOVT_ABS
#undef R_ARM_THM_MOVW_PREL_NC
#undef R_ARM_THM_MOVT_PREL
#undef R_ARM_THM_JUMP19
#undef R_ARM_THM_JUMP6
#undef R_ARM_THM_ALU_PREL_11_0
#undef R_ARM_THM_PC12
#undef R_ARM_ABS32_NOI
#undef R_ARM_REL32_NOI
#undef R_ARM_ALU_PC_G0_NC
#undef R_ARM_ALU_PC_G0
#undef R_ARM_ALU_PC_G1_NC
#undef R_ARM_ALU_PC_G1
#undef R_ARM_ALU_PC_G2
#undef R_ARM_LDR_PC_G1
#undef R_ARM_LDR_PC_G2
#undef R_ARM_LDRS_PC_G0
#undef R_ARM_LDRS_PC_G1
#undef R_ARM_LDRS_PC_G2
#undef R_ARM_LDC_PC_G0
#undef R_ARM_LDC_PC_G1
#undef R_ARM_LDC_PC_G2
#undef R_ARM_ALU_SB_G0_NC
#undef R_ARM_ALU_SB_G0
#undef R_ARM_ALU_SB_G1_NC
#undef R_ARM_ALU_SB_G1
#undef R_ARM_ALU_SB_G2
#undef R_ARM_LDR_SB_G0
#undef R_ARM_LDR_SB_G1
#undef R_ARM_LDR_SB_G2
#undef R_ARM_LDRS_SB_G0
#undef R_ARM_LDRS_SB_G1
#undef R_ARM_LDRS_SB_G2
#undef R_ARM_LDC_SB_G0
#undef R_ARM_LDC_SB_G1
#undef R_ARM_LDC_SB_G2
#undef R_ARM_MOVW_BREL_NC
#undef R_ARM_MOVT_BREL
#undef R_ARM_MOVW_BREL
#undef R_ARM_THM_MOVW_BREL_NC
#undef R_ARM_THM_MOVT_BREL
#undef R_ARM_THM_MOVW_BREL
#undef R_ARM_TLS_GOTDESC
#undef R_ARM_TLS_CALL
#undef R_ARM_TLS_DESCSEQ
#undef R_ARM_THM_TLS_CALL
#undef R_ARM_PLT32_ABS
#undef R_ARM_GOT_ABS
#undef R_ARM_GOT_PREL
#undef R_ARM_GOT_BREL12
#undef R_ARM_GOTOFF12
#undef R_ARM_GOTRELAX
#undef R_ARM_GNU_VTENTRY
#undef R_ARM_GNU_VTINHERIT
#undef R_ARM_THM_JUMP11
#undef R_ARM_THM_JUMP8
#undef R_ARM_TLS_GD32
#undef R_ARM_TLS_LDM32
#undef R_ARM_TLS_LDO32
#undef R_ARM_TLS_IE32
#undef R_ARM_TLS_LE32
#undef R_ARM_TLS_LDO12
#undef R_ARM_TLS_LE12
#undef R_ARM_TLS_IE12GP
#undef R_ARM_PRIVATE_0
#undef R_ARM_PRIVATE_1
#undef R_ARM_PRIVATE_2
#undef R_ARM_PRIVATE_3
#undef R_ARM_PRIVATE_4
#undef R_ARM_PRIVATE_5
#undef R_ARM_PRIVATE_6
#undef R_ARM_PRIVATE_7
#undef R_ARM_PRIVATE_8
#undef R_ARM_PRIVATE_9
#undef R_ARM_PRIVATE_10
#undef R_ARM_PRIVATE_11
#undef R_ARM_PRIVATE_12
#undef R_ARM_PRIVATE_13
#undef R_ARM_PRIVATE_14
#undef R_ARM_PRIVATE_15
#undef R_ARM_ME_TOO
#undef R_ARM_THM_TLS_DESCSEQ16
#undef R_ARM_THM_TLS_DESCSEQ32
#undef R_ARM_IRELATIVE

#undef R_ARM_RXPC25
#undef R_ARM_RSBREL32
#undef R_ARM_THM_RPC22
#undef R_ARM_RREL32
#undef R_ARM_RPC24
#undef R_ARM_RBASE

#undef R_HEX_NONE
#undef R_HEX_B22_PCREL
#undef R_HEX_B15_PCREL
#undef R_HEX_B7_PCREL
#undef R_HEX_LO16
#undef R_HEX_HI16
#undef R_HEX_32
#undef R_HEX_16
#undef R_HEX_8
#undef R_HEX_GPREL16_0
#undef R_HEX_GPREL16_1
#undef R_HEX_GPREL16_2
#undef R_HEX_GPREL16_3
#undef R_HEX_HL16
#undef R_HEX_B13_PCREL
#undef R_HEX_B9_PCREL
#undef R_HEX_B32_PCREL_X
#undef R_HEX_32_6_X
#undef R_HEX_B22_PCREL_X
#undef R_HEX_B15_PCREL_X
#undef R_HEX_B13_PCREL_X
#undef R_HEX_B9_PCREL_X
#undef R_HEX_B7_PCREL_X
#undef R_HEX_16_X
#undef R_HEX_12_X
#undef R_HEX_11_X
#undef R_HEX_10_X
#undef R_HEX_9_X
#undef R_HEX_8_X
#undef R_HEX_7_X
#undef R_HEX_6_X
#undef R_HEX_32_PCREL
#undef R_HEX_COPY
#undef R_HEX_GLOB_DAT
#undef R_HEX_JMP_SLOT
#undef R_HEX_RELATIVE
#undef R_HEX_PLT_B22_PCREL
#undef R_HEX_GOTREL_LO16
#undef R_HEX_GOTREL_HI16
#undef R_HEX_GOTREL_32
#undef R_HEX_GOT_LO16
#undef R_HEX_GOT_HI16
#undef R_HEX_GOT_32
#undef R_HEX_GOT_16
#undef R_HEX_DTPMOD_32
#undef R_HEX_DTPREL_LO16
#undef R_HEX_DTPREL_HI16
#undef R_HEX_DTPREL_32
#undef R_HEX_DTPREL_16
#undef R_HEX_GD_PLT_B22_PCREL
#undef R_HEX_GD_GOT_LO16
#undef R_HEX_GD_GOT_HI16
#undef R_HEX_GD_GOT_32
#undef R_HEX_GD_GOT_16
#undef R_HEX_IE_LO16
#undef R_HEX_IE_HI16
#undef R_HEX_IE_32
#undef R_HEX_IE_GOT_LO16
#undef R_HEX_IE_GOT_HI16
#undef R_HEX_IE_GOT_32
#undef R_HEX_IE_GOT_16
#undef R_HEX_TPREL_LO16
#undef R_HEX_TPREL_HI16
#undef R_HEX_TPREL_32
#undef R_HEX_TPREL_16
#undef R_HEX_6_PCREL_X
#undef R_HEX_GOTREL_32_6_X
#undef R_HEX_GOTREL_16_X
#undef R_HEX_GOTREL_11_X
#undef R_HEX_GOT_32_6_X
#undef R_HEX_GOT_16_X
#undef R_HEX_GOT_11_X
#undef R_HEX_DTPREL_32_6_X
#undef R_HEX_DTPREL_16_X
#undef R_HEX_DTPREL_11_X
#undef R_HEX_GD_GOT_32_6_X
#undef R_HEX_GD_GOT_16_X
#undef R_HEX_GD_GOT_11_X
#undef R_HEX_IE_32_6_X
#undef R_HEX_IE_16_X
#undef R_HEX_IE_GOT_32_6_X
#undef R_HEX_IE_GOT_16_X
#undef R_HEX_IE_GOT_11_X
#undef R_HEX_TPREL_32_6_X
#undef R_HEX_TPREL_16_X
#undef R_HEX_TPREL_11_X
#undef R_HEX_LD_PLT_B22_PCREL
#undef R_HEX_LD_GOT_LO16
#undef R_HEX_LD_GOT_HI16
#undef R_HEX_LD_GOT_32
#undef R_HEX_LD_GOT_16
#undef R_HEX_LD_GOT_32_6_X
#undef R_HEX_LD_GOT_16_X
#undef R_HEX_LD_GOT_11_X

#undef R_386_NONE
#undef R_386_32
#undef R_386_PC32
#undef R_386_GOT32
#undef R_386_PLT32
#undef R_386_COPY
#undef R_386_GLOB_DAT
#undef R_386_JUMP_SLOT
#undef R_386_RELATIVE
#undef R_386_GOTOFF
#undef R_386_GOTPC
#undef R_386_32PLT
#undef R_386_TLS_TPOFF
#undef R_386_TLS_IE
#undef R_386_TLS_GOTIE
#undef R_386_TLS_LE
#undef R_386_TLS_GD
#undef R_386_TLS_LDM
#undef R_386_16
#undef R_386_PC16
#undef R_386_8
#undef R_386_PC8
#undef R_386_TLS_GD_32
#undef R_386_TLS_GD_PUSH
#undef R_386_TLS_GD_CALL
#undef R_386_TLS_GD_POP
#undef R_386_TLS_LDM_32
#undef R_386_TLS_LDM_PUSH
#undef R_386_TLS_LDM_CALL
#undef R_386_TLS_LDM_POP
#undef R_386_TLS_LDO_32
#undef R_386_TLS_IE_32
#undef R_386_TLS_LE_32
#undef R_386_TLS_DTPMOD32
#undef R_386_TLS_DTPOFF32
#undef R_386_TLS_TPOFF32
#undef R_386_TLS_GOTDESC
#undef R_386_TLS_DESC_CALL
#undef R_386_TLS_DESC
#undef R_386_IRELATIVE
#undef R_386_NUM

#undef R_MIPS_NONE
#undef R_MIPS_16
#undef R_MIPS_32
#undef R_MIPS_REL32
#undef R_MIPS_26
#undef R_MIPS_HI16
#undef R_MIPS_LO16
#undef R_MIPS_GPREL16
#undef R_MIPS_LITERAL
#undef R_MIPS_GOT16
#undef R_MIPS_PC16
#undef R_MIPS_CALL16
#undef R_MIPS_GPREL32
#undef R_MIPS_UNUSED1
#undef R_MIPS_UNUSED2
#undef R_MIPS_UNUSED3
#undef R_MIPS_SHIFT5
#undef R_MIPS_SHIFT6
#undef R_MIPS_64
#undef R_MIPS_GOT_DISP
#undef R_MIPS_GOT_PAGE
#undef R_MIPS_GOT_OFST
#undef R_MIPS_GOT_HI16
#undef R_MIPS_GOT_LO16
#undef R_MIPS_SUB
#undef R_MIPS_INSERT_A
#undef R_MIPS_INSERT_B
#undef R_MIPS_DELETE
#undef R_MIPS_HIGHER
#undef R_MIPS_HIGHEST
#undef R_MIPS_CALL_HI16
#undef R_MIPS_CALL_LO16
#undef R_MIPS_SCN_DISP
#undef R_MIPS_REL16
#undef R_MIPS_ADD_IMMEDIATE
#undef R_MIPS_PJUMP
#undef R_MIPS_RELGOT
#undef R_MIPS_JALR
#undef R_MIPS_TLS_DTPMOD32
#undef R_MIPS_TLS_DTPREL32
#undef R_MIPS_TLS_DTPMOD64
#undef R_MIPS_TLS_DTPREL64
#undef R_MIPS_TLS_GD
#undef R_MIPS_TLS_LDM
#undef R_MIPS_TLS_DTPREL_HI16
#undef R_MIPS_TLS_DTPREL_LO16
#undef R_MIPS_TLS_GOTTPREL
#undef R_MIPS_TLS_TPREL32
#undef R_MIPS_TLS_TPREL64
#undef R_MIPS_TLS_TPREL_HI16
#undef R_MIPS_TLS_TPREL_LO16
#undef R_MIPS_GLOB_DAT
#undef R_MIPS_PC21_S2
#undef R_MIPS_PC26_S2
#undef R_MIPS_PC18_S3
#undef R_MIPS_PC19_S2
#undef R_MIPS_PCHI16
#undef R_MIPS_PCLO16
#undef R_MIPS16_26
#undef R_MIPS16_GPREL
#undef R_MIPS16_GOT16
#undef R_MIPS16_CALL16
#undef R_MIPS16_HI16
#undef R_MIPS16_LO16
#undef R_MIPS16_TLS_GD
#undef R_MIPS16_TLS_LDM
#undef R_MIPS16_TLS_DTPREL_HI16
#undef R_MIPS16_TLS_DTPREL_LO16
#undef R_MIPS16_TLS_GOTTPREL
#undef R_MIPS16_TLS_TPREL_HI16
#undef R_MIPS16_TLS_TPREL_LO16
#undef R_MIPS_COPY
#undef R_MIPS_JUMP_SLOT
#undef R_MICROMIPS_26_S1
#undef R_MICROMIPS_HI16
#undef R_MICROMIPS_LO16
#undef R_MICROMIPS_GPREL16
#undef R_MICROMIPS_LITERAL
#undef R_MICROMIPS_GOT16
#undef R_MICROMIPS_PC7_S1
#undef R_MICROMIPS_PC10_S1
#undef R_MICROMIPS_PC16_S1
#undef R_MICROMIPS_CALL16
#undef R_MICROMIPS_GOT_DISP
#undef R_MICROMIPS_GOT_PAGE
#undef R_MICROMIPS_GOT_OFST
#undef R_MICROMIPS_GOT_HI16
#undef R_MICROMIPS_GOT_LO16
#undef R_MICROMIPS_SUB
#undef R_MICROMIPS_HIGHER
#undef R_MICROMIPS_HIGHEST
#undef R_MICROMIPS_CALL_HI16
#undef R_MICROMIPS_CALL_LO16
#undef R_MICROMIPS_SCN_DISP
#undef R_MICROMIPS_JALR
#undef R_MICROMIPS_HI0_LO16
#undef R_MICROMIPS_TLS_GD
#undef R_MICROMIPS_TLS_LDM
#undef R_MICROMIPS_TLS_DTPREL_HI16
#undef R_MICROMIPS_TLS_DTPREL_LO16
#undef R_MICROMIPS_TLS_GOTTPREL
#undef R_MICROMIPS_TLS_TPREL_HI16
#undef R_MICROMIPS_TLS_TPREL_LO16
#undef R_MICROMIPS_GPREL7_S2
#undef R_MICROMIPS_PC23_S2
#undef R_MICROMIPS_PC21_S2
#undef R_MICROMIPS_PC26_S2
#undef R_MICROMIPS_PC18_S3
#undef R_MICROMIPS_PC19_S2
#undef R_MIPS_NUM
#undef R_MIPS_PC32
#undef R_MIPS_EH

#undef R_PPC_NONE
#undef R_PPC_ADDR32
#undef R_PPC_ADDR24
#undef R_PPC_ADDR16
#undef R_PPC_ADDR16_LO
#undef R_PPC_ADDR16_HI
#undef R_PPC_ADDR16_HA
#undef R_PPC_ADDR14
#undef R_PPC_ADDR14_BRTAKEN
#undef R_PPC_ADDR14_BRNTAKEN
#undef R_PPC_REL24
#undef R_PPC_REL14
#undef R_PPC_REL14_BRTAKEN
#undef R_PPC_REL14_BRNTAKEN
#undef R_PPC_GOT16
#undef R_PPC_GOT16_LO
#undef R_PPC_GOT16_HI
#undef R_PPC_GOT16_HA
#undef R_PPC_PLTREL24
#undef R_PPC_JMP_SLOT
#undef R_PPC_RELATIVE
#undef R_PPC_LOCAL24PC
#undef R_PPC_REL32
#undef R_PPC_TLS
#undef R_PPC_DTPMOD32
#undef R_PPC_TPREL16
#undef R_PPC_TPREL16_LO
#undef R_PPC_TPREL16_HI
#undef R_PPC_TPREL16_HA
#undef R_PPC_TPREL32
#undef R_PPC_DTPREL16
#undef R_PPC_DTPREL16_LO
#undef R_PPC_DTPREL16_HI
#undef R_PPC_DTPREL16_HA
#undef R_PPC_DTPREL32
#undef R_PPC_GOT_TLSGD16
#undef R_PPC_GOT_TLSGD16_LO
#undef R_PPC_GOT_TLSGD16_HI
#undef R_PPC_GOT_TLSGD16_HA
#undef R_PPC_GOT_TLSLD16
#undef R_PPC_GOT_TLSLD16_LO
#undef R_PPC_GOT_TLSLD16_HI
#undef R_PPC_GOT_TLSLD16_HA
#undef R_PPC_GOT_TPREL16
#undef R_PPC_GOT_TPREL16_LO
#undef R_PPC_GOT_TPREL16_HI
#undef R_PPC_GOT_TPREL16_HA
#undef R_PPC_GOT_DTPREL16
#undef R_PPC_GOT_DTPREL16_LO
#undef R_PPC_GOT_DTPREL16_HI
#undef R_PPC_GOT_DTPREL16_HA
#undef R_PPC_TLSGD
#undef R_PPC_TLSLD
#undef R_PPC_REL16
#undef R_PPC_REL16_LO
#undef R_PPC_REL16_HI
#undef R_PPC_REL16_HA

#undef R_PPC64_NONE
#undef R_PPC64_ADDR32
#undef R_PPC64_ADDR24
#undef R_PPC64_ADDR16
#undef R_PPC64_ADDR16_LO
#undef R_PPC64_ADDR16_HI
#undef R_PPC64_ADDR16_HA
#undef R_PPC64_ADDR14
#undef R_PPC64_ADDR14_BRTAKEN
#undef R_PPC64_ADDR14_BRNTAKEN
#undef R_PPC64_REL24
#undef R_PPC64_REL14
#undef R_PPC64_REL14_BRTAKEN
#undef R_PPC64_REL14_BRNTAKEN
#undef R_PPC64_GOT16
#undef R_PPC64_GOT16_LO
#undef R_PPC64_GOT16_HI
#undef R_PPC64_GOT16_HA
#undef R_PPC64_JMP_SLOT
#undef R_PPC64_RELATIVE
#undef R_PPC64_REL32
#undef R_PPC64_ADDR64
#undef R_PPC64_ADDR16_HIGHER
#undef R_PPC64_ADDR16_HIGHERA
#undef R_PPC64_ADDR16_HIGHEST
#undef R_PPC64_ADDR16_HIGHESTA
#undef R_PPC64_REL64
#undef R_PPC64_TOC16
#undef R_PPC64_TOC16_LO
#undef R_PPC64_TOC16_HI
#undef R_PPC64_TOC16_HA
#undef R_PPC64_TOC
#undef R_PPC64_ADDR16_DS
#undef R_PPC64_ADDR16_LO_DS
#undef R_PPC64_GOT16_DS
#undef R_PPC64_GOT16_LO_DS
#undef R_PPC64_TOC16_DS
#undef R_PPC64_TOC16_LO_DS
#undef R_PPC64_TLS
#undef R_PPC64_DTPMOD64
#undef R_PPC64_TPREL16
#undef R_PPC64_TPREL16_LO
#undef R_PPC64_TPREL16_HI
#undef R_PPC64_TPREL16_HA
#undef R_PPC64_TPREL64
#undef R_PPC64_DTPREL16
#undef R_PPC64_DTPREL16_LO
#undef R_PPC64_DTPREL16_HI
#undef R_PPC64_DTPREL16_HA
#undef R_PPC64_DTPREL64
#undef R_PPC64_GOT_TLSGD16
#undef R_PPC64_GOT_TLSGD16_LO
#undef R_PPC64_GOT_TLSGD16_HI
#undef R_PPC64_GOT_TLSGD16_HA
#undef R_PPC64_GOT_TLSLD16
#undef R_PPC64_GOT_TLSLD16_LO
#undef R_PPC64_GOT_TLSLD16_HI
#undef R_PPC64_GOT_TLSLD16_HA
#undef R_PPC64_GOT_TPREL16_DS
#undef R_PPC64_GOT_TPREL16_LO_DS
#undef R_PPC64_GOT_TPREL16_HI
#undef R_PPC64_GOT_TPREL16_HA
#undef R_PPC64_GOT_DTPREL16_DS
#undef R_PPC64_GOT_DTPREL16_LO_DS
#undef R_PPC64_GOT_DTPREL16_HI
#undef R_PPC64_GOT_DTPREL16_HA
#undef R_PPC64_TPREL16_DS
#undef R_PPC64_TPREL16_LO_DS
#undef R_PPC64_TPREL16_HIGHER
#undef R_PPC64_TPREL16_HIGHERA
#undef R_PPC64_TPREL16_HIGHEST
#undef R_PPC64_TPREL16_HIGHESTA
#undef R_PPC64_DTPREL16_DS
#undef R_PPC64_DTPREL16_LO_DS
#undef R_PPC64_DTPREL16_HIGHER
#undef R_PPC64_DTPREL16_HIGHERA
#undef R_PPC64_DTPREL16_HIGHEST
#undef R_PPC64_DTPREL16_HIGHESTA
#undef R_PPC64_TLSGD
#undef R_PPC64_TLSLD
#undef R_PPC64_REL16
#undef R_PPC64_REL16_LO
#undef R_PPC64_REL16_HI
#undef R_PPC64_REL16_HA

#undef R_SPARC_NONE
#undef R_SPARC_8
#undef R_SPARC_16
#undef R_SPARC_32
#undef R_SPARC_DISP8
#undef R_SPARC_DISP16
#undef R_SPARC_DISP32
#undef R_SPARC_WDISP30
#undef R_SPARC_WDISP22
#undef R_SPARC_HI22
#undef R_SPARC_22
#undef R_SPARC_13
#undef R_SPARC_LO10
#undef R_SPARC_GOT10
#undef R_SPARC_GOT13
#undef R_SPARC_GOT22
#undef R_SPARC_PC10
#undef R_SPARC_PC22
#undef R_SPARC_WPLT30
#undef R_SPARC_COPY
#undef R_SPARC_GLOB_DAT
#undef R_SPARC_JMP_SLOT
#undef R_SPARC_RELATIVE
#undef R_SPARC_UA32
#undef R_SPARC_PLT32
#undef R_SPARC_HIPLT22
#undef R_SPARC_LOPLT10
#undef R_SPARC_PCPLT32
#undef R_SPARC_PCPLT22
#undef R_SPARC_PCPLT10
#undef R_SPARC_10
#undef R_SPARC_11
#undef R_SPARC_64
#undef R_SPARC_OLO10
#undef R_SPARC_HH22
#undef R_SPARC_HM10
#undef R_SPARC_LM22
#undef R_SPARC_PC_HH22
#undef R_SPARC_PC_HM10
#undef R_SPARC_PC_LM22
#undef R_SPARC_WDISP16
#undef R_SPARC_WDISP19
#undef R_SPARC_7
#undef R_SPARC_5
#undef R_SPARC_6
#undef R_SPARC_DISP64
#undef R_SPARC_PLT64
#undef R_SPARC_HIX22
#undef R_SPARC_LOX10
#undef R_SPARC_H44
#undef R_SPARC_M44
#undef R_SPARC_L44
#undef R_SPARC_REGISTER
#undef R_SPARC_UA64
#undef R_SPARC_UA16
#undef R_SPARC_TLS_GD_HI22
#undef R_SPARC_TLS_GD_LO10
#undef R_SPARC_TLS_GD_ADD
#undef R_SPARC_TLS_GD_CALL
#undef R_SPARC_TLS_LDM_HI22
#undef R_SPARC_TLS_LDM_LO10
#undef R_SPARC_TLS_LDM_ADD
#undef R_SPARC_TLS_LDM_CALL
#undef R_SPARC_TLS_LDO_HIX22
#undef R_SPARC_TLS_LDO_LOX10
#undef R_SPARC_TLS_LDO_ADD
#undef R_SPARC_TLS_IE_HI22
#undef R_SPARC_TLS_IE_LO10
#undef R_SPARC_TLS_IE_LD
#undef R_SPARC_TLS_IE_LDX
#undef R_SPARC_TLS_IE_ADD
#undef R_SPARC_TLS_LE_HIX22
#undef R_SPARC_TLS_LE_LOX10
#undef R_SPARC_TLS_DTPMOD32
#undef R_SPARC_TLS_DTPMOD64
#undef R_SPARC_TLS_DTPOFF32
#undef R_SPARC_TLS_DTPOFF64
#undef R_SPARC_TLS_TPOFF32
#undef R_SPARC_TLS_TPOFF64
#undef R_SPARC_GOTDATA_HIX22
#undef R_SPARC_GOTDATA_LOX10
#undef R_SPARC_GOTDATA_OP_HIX22
#undef R_SPARC_GOTDATA_OP_LOX10
#undef R_SPARC_GOTDATA_OP

#undef R_390_NONE
#undef R_390_8
#undef R_390_12
#undef R_390_16
#undef R_390_32
#undef R_390_PC32
#undef R_390_GOT12
#undef R_390_GOT32
#undef R_390_PLT32
#undef R_390_COPY
#undef R_390_GLOB_DAT
#undef R_390_JMP_SLOT
#undef R_390_RELATIVE
#undef R_390_GOTOFF
#undef R_390_GOTPC
#undef R_390_GOT16
#undef R_390_PC16
#undef R_390_PC16DBL
#undef R_390_PLT16DBL
#undef R_390_PC32DBL
#undef R_390_PLT32DBL
#undef R_390_GOTPCDBL
#undef R_390_64
#undef R_390_PC64
#undef R_390_GOT64
#undef R_390_PLT64
#undef R_390_GOTENT
#undef R_390_GOTOFF16
#undef R_390_GOTOFF64
#undef R_390_GOTPLT12
#undef R_390_GOTPLT16
#undef R_390_GOTPLT32
#undef R_390_GOTPLT64
#undef R_390_GOTPLTENT
#undef R_390_PLTOFF16
#undef R_390_PLTOFF32
#undef R_390_PLTOFF64
#undef R_390_TLS_LOAD
#undef R_390_TLS_GDCALL
#undef R_390_TLS_LDCALL
#undef R_390_TLS_GD32
#undef R_390_TLS_GD64
#undef R_390_TLS_GOTIE12
#undef R_390_TLS_GOTIE32
#undef R_390_TLS_GOTIE64
#undef R_390_TLS_LDM32
#undef R_390_TLS_LDM64
#undef R_390_TLS_IE32
#undef R_390_TLS_IE64
#undef R_390_TLS_IEENT
#undef R_390_TLS_LE32
#undef R_390_TLS_LE64
#undef R_390_TLS_LDO32
#undef R_390_TLS_LDO64
#undef R_390_TLS_DTPMOD
#undef R_390_TLS_DTPOFF
#undef R_390_TLS_TPOFF
#undef R_390_20
#undef R_390_GOT20
#undef R_390_GOTPLT20
#undef R_390_TLS_GOTIE20
#undef R_390_IRELATIVE

#undef R_X86_64_NONE
#undef R_X86_64_64
#undef R_X86_64_PC32
#undef R_X86_64_GOT32
#undef R_X86_64_PLT32
#undef R_X86_64_COPY
#undef R_X86_64_GLOB_DAT
#undef R_X86_64_JUMP_SLOT
#undef R_X86_64_RELATIVE
#undef R_X86_64_GOTPCREL
#undef R_X86_64_32
#undef R_X86_64_32S
#undef R_X86_64_16
#undef R_X86_64_PC16
#undef R_X86_64_8
#undef R_X86_64_PC8
#undef R_X86_64_DTPMOD64
#undef R_X86_64_DTPOFF64
#undef R_X86_64_TPOFF64
#undef R_X86_64_TLSGD
#undef R_X86_64_TLSLD
#undef R_X86_64_DTPOFF32
#undef R_X86_64_GOTTPOFF
#undef R_X86_64_TPOFF32
#undef R_X86_64_PC64
#undef R_X86_64_GOTOFF64
#undef R_X86_64_GOTPC32
#undef R_X86_64_GOT64
#undef R_X86_64_GOTPCREL64
#undef R_X86_64_GOTPC64
#undef R_X86_64_GOTPLT64
#undef R_X86_64_PLTOFF64
#undef R_X86_64_SIZE32
#undef R_X86_64_SIZE64
#undef R_X86_64_GOTPC32_TLSDESC
#undef R_X86_64_TLSDESC_CALL
#undef R_X86_64_TLSDESC
#undef R_X86_64_IRELATIVE

#undef R_X86_64_RELATIVE64
#undef R_X86_64_PC32_BND
#undef R_X86_64_PLT32_BND
#undef R_X86_64_GOTPCRELX
#undef R_X86_64_REX_GOTPCRELX

#undef R_LARCH_NONE
#undef R_LARCH_32
#undef R_LARCH_64
#undef R_LARCH_RELATIVE
#undef R_LARCH_COPY
#undef R_LARCH_JUMP_SLOT
#undef R_LARCH_TLS_DTPMOD32
#undef R_LARCH_TLS_DTPMOD64
#undef R_LARCH_TLS_DTPREL32
#undef R_LARCH_TLS_DTPREL64
#undef R_LARCH_TLS_TPREL32
#undef R_LARCH_TLS_TPREL64
#undef R_LARCH_IRELATIVE
#undef R_LARCH_MARK_LA
#undef R_LARCH_MARK_PCREL
#undef R_LARCH_SOP_PUSH_PCREL
#undef R_LARCH_SOP_PUSH_ABSOLUTE
#undef R_LARCH_SOP_PUSH_DUP
#undef R_LARCH_SOP_PUSH_GPREL
#undef R_LARCH_SOP_PUSH_TLS_TPREL
#undef R_LARCH_SOP_PUSH_TLS_GOT
#undef R_LARCH_SOP_PUSH_TLS_GD
#undef R_LARCH_SOP_PUSH_PLT_PCREL
#undef R_LARCH_SOP_ASSERT
#undef R_LARCH_SOP_NOT
#undef R_LARCH_SOP_SUB
#undef R_LARCH_SOP_SL
#undef R_LARCH_SOP_SR
#undef R_LARCH_SOP_ADD
#undef R_LARCH_SOP_AND
#undef R_LARCH_SOP_IF_ELSE
#undef R_LARCH_SOP_POP_32_S_10_5
#undef R_LARCH_SOP_POP_32_U_10_12
#undef R_LARCH_SOP_POP_32_S_10_12
#undef R_LARCH_SOP_POP_32_S_10_16
#undef R_LARCH_SOP_POP_32_S_10_16_S2
#undef R_LARCH_SOP_POP_32_S_5_20
#undef R_LARCH_SOP_POP_32_S_0_5_10_16_S2
#undef R_LARCH_SOP_POP_32_S_0_10_10_16_S2
#undef R_LARCH_SOP_POP_32_U
#undef R_LARCH_ADD8
#undef R_LARCH_ADD16
#undef R_LARCH_ADD24
#undef R_LARCH_ADD32
#undef R_LARCH_ADD64
#undef R_LARCH_SUB8
#undef R_LARCH_SUB16
#undef R_LARCH_SUB24
#undef R_LARCH_SUB32
#undef R_LARCH_SUB64
#undef R_LARCH_GNU_VTINHERIT
#undef R_LARCH_GNU_VTENTRY
#undef R_LARCH_B16
#undef R_LARCH_B21
#undef R_LARCH_B26
#undef R_LARCH_ABS_HI20
#undef R_LARCH_ABS_LO12
#undef R_LARCH_ABS64_LO20
#undef R_LARCH_ABS64_HI12
#undef R_LARCH_PCALA_HI20
#undef R_LARCH_PCALA_LO12
#undef R_LARCH_PCALA64_LO20
#undef R_LARCH_PCALA64_HI12
#undef R_LARCH_GOT_PC_HI20
#undef R_LARCH_GOT_PC_LO12
#undef R_LARCH_GOT64_PC_LO20
#undef R_LARCH_GOT64_PC_HI12
#undef R_LARCH_GOT_HI20
#undef R_LARCH_GOT_LO12
#undef R_LARCH_GOT64_LO20
#undef R_LARCH_GOT64_HI12
#undef R_LARCH_TLS_LE_HI20
#undef R_LARCH_TLS_LE_LO12
#undef R_LARCH_TLS_LE64_LO20
#undef R_LARCH_TLS_LE64_HI12
#undef R_LARCH_TLS_IE_PC_HI20
#undef R_LARCH_TLS_IE_PC_LO12
#undef R_LARCH_TLS_IE64_PC_LO20
#undef R_LARCH_TLS_IE64_PC_HI12
#undef R_LARCH_TLS_IE_HI20
#undef R_LARCH_TLS_IE_LO12
#undef R_LARCH_TLS_IE64_LO20
#undef R_LARCH_TLS_IE64_HI12
#undef R_LARCH_TLS_LD_PC_HI20
#undef R_LARCH_TLS_LD_HI20
#undef R_LARCH_TLS_GD_PC_HI20
#undef R_LARCH_TLS_GD_HI20
#undef R_LARCH_32_PCREL
#undef R_LARCH_RELAX

#undef AT_NULL
#undef AT_IGNORE
#undef AT_EXECFD
#undef AT_PHDR
#undef AT_PHENT
#undef AT_PHNUM
#undef AT_PAGESZ
#undef AT_BASE
#undef AT_FLAGS
#undef AT_ENTRY
#undef AT_NOTELF
#undef AT_UID
#undef AT_EUID
#undef AT_GID
#undef AT_EGID
#undef AT_CLKTCK

#undef AT_PLATFORM
#undef AT_HWCAP
#undef AT_HWCAP2
#undef AT_FPUCW
#undef AT_DCACHEBSIZE
#undef AT_ICACHEBSIZE
#undef AT_UCACHEBSIZE
#undef AT_IGNOREPPC
#undef AT_SECURE
#undef AT_BASE_PLATFORM
#undef AT_RANDOM
#undef AT_EXECFN
#undef AT_SYSINFO
#undef AT_SYSINFO_EHDR
#undef AT_L1I_CACHESHAPE
#undef AT_L1D_CACHESHAPE
#undef AT_L2_CACHESHAPE
#undef AT_L3_CACHESHAPE

#undef NT_GNU_PROPERTY_TYPE_0


#endif
