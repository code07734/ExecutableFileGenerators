#include "nctypes.h"

class elfFile
{
public:
	enum fileType{none,reloc,exec,shared,core};
	enum machineType{x86 = 3, arm = 0x28, x64 = 0x3e, arm64 = 0xb7, riscv = 0xf3};
	enum osABI{systemV, NetBSD = 2, Linux = 3, FreeBSD = 9, OpenBSD = 0xc};
	enum endianness{LE = 1, BE = 2}; 
	enum phType{phNull,phLoad,phDynamic,phInterp,phNote,phShlib,phPhdr,phThreadLocalStorage};
	enum linkness{staticLink, dynamicLink = 3};
void elfgen(u8 *p, u32 len, u32 fileType, u32 machineType, u32 osABI, u32 endianness, u32 phType){
	u32 c=0, *ptr;
	ptr=(u32*)p;
	
	struct elf64
	{
		u32 signature;
		u8 archWordSize;//1 - 32bit, 2 - 64bit
		u8 endianness;
		u8 relFileVersion; //1
		u8 osABI;
		u64 libABI;
		u16 fileType;
		u16 machineType;
		u32 fileVersion;
		u64 entryPoint;
		u64 phoff;
		u64 shoff;
		u32 flags; // depends on target arch
		u16 sizeFileHeader;
		u16 sizeProgramHeader;
		u16 nOfEntriesInPH;
		u16 sizeSecHeader;
		u16 nOfentriesInSecH;
		u16 indexOfSecHTEofNames;
	};elf64 *elf;
	struct elf64ph //ph - means Program Header
	{
		u32 phType;
		u32 phFlags;
		u64 phSegOffset;
		u64 phVA;
		u64 phPA;
		u64 phFileSize;
		u64 phMemSize;
		u64 alignment;//0,1 - no alignment. Alignment = 2^n
		
	};elf64ph *elfph;
	
	elf = (elf64*)p;
	elf->signature = 0x464c457f;
	elf->archWordSize = 2;
	elf->endianness = endianness;
	elf->relFileVersion = 1;
	elf->osABI = osABI;
	elf->libABI = 0;
	elf->fileType = fileType;
	elf->machineType = machineType;
	elf->fileVersion = 1;
	elf->entryPoint = 0x00400078;
	elf->phoff = 0x40;
	elf->shoff = 0;
	elf->flags = 0;
	elf->sizeFileHeader = 0x40;
	elf->sizeProgramHeader = 0x38;
	elf->nOfEntriesInPH = 1;
	elf->sizeSecHeader = 0x40;
	elf->nOfentriesInSecH = 0;
	elf->indexOfSecHTEofNames = 0;

	elfph = (elf64ph*)(p + elf->phoff);
	elfph->phType = phType;
	elfph->phFlags = 5;
	elfph->phSegOffset = 0;
	elfph->phVA = 0x00400000;
	elfph->phPA = 0x00400000;
	elfph->phFileSize = len + elf->entryPoint - elfph->phVA;
	elfph->phMemSize = len + elf->entryPoint - elfph->phPA;
	elfph->alignment = 1;
	}
};


class pe_gen
{
public:
    void init(u32 len, u8 *p){
    	PE *pe;
    	pe=(PE*)p;
 
	    pe[0]={0x5a4d,0xccccffff};
	    pe[1].signature=0x5a4c;
	    pe[1].peSecOffset=0x5a4c;
 
	    pe+=1;
	    (pe+1)->signature=0x5a4c;
	    (pe+1)->peSecOffset=0x5a4c;
	}
private:
	struct PE{
        u16 signature;
        //u8 dosStub[0x3a];
        u32 peSecOffset;
    };
};
