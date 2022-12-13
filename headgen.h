#include "nctypes.h"

class elfFile
{
public:
	enum archWordSize{w32=1 ,w64=2};
	enum fileType{none,reloc,exec,shared,core};
	enum machineType{x86=3, arm=0x28, x64=0x3e, arm64=0xb7, riscv=0xf3};
	enum osABI{systemV, NetBSD=2, Linux=3, FreeBSD=9, OpenBSD=0xc};//systemV is used
	enum endianness{LE=1, BE=2}; 
	enum phType{phNull,phLoad,phDynamic,phInterp,phNote,phShlib,phPhdr,phThreadLocalStorage};
	enum linkness{staticLink, dynamicLink=3};
	
	struct elf64
	{
		u32 signature;
		u8 archWordSize,
			endianness,
			relFileVersion,
			osABI;
		u64 libABI;
		u16 fileType,
			machineType;
		u32 fileVersion;
		u64 entryPoint,
			phoff,
			shoff;
		u32 flags; // depends on target arch
		u16 sizeFileHeader,
			sizeProgramHeader,
			nOfEntriesInPH,
			sizeSecHeader,
			nOfentriesInSecH,
			indexOfSecHTEofNames;
	};elf64 *elf;

	struct elfph64 //ph - means Program Header
	{
		u32 phType,phFlags;
		u64 phSegOffset,phVA,phPA,phFileSize,phMemSize,alignment;
		//0,1 - no alignment. Alignment = 2^n
	};elfph64 *elfph;

	void init(u8 *p, u32 len, u32 archWordSize, u32 fileType, u32 machineType, u32 osABI, u32 endianness, u32 phType){

		elf=(elf64*)p;
		elf->signature = 0x464c457f;
		elf->archWordSize = archWordSize;
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

		elfph=(elfph64*)(p + elf->phoff);
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


class peFile
{
public:
	enum machineType{x64=0x8664, x86=0x14c, arm_le=0x1c0, armThumb2_le=0x1c4, arm64_le=0xaa64, 
		riscv32=0x5032, riscv64=0x5064, efiByteCode=0xebc};
	enum opHsignature{pe32=0x10b,pe32plus=0x20b,rom=0x107};
	enum subSystem{ssUnknown,ssDeviceDriver,ssGui,ssChar,ssEfiApp=10,ssEfiBoot,ssEfiDriver,ssEfiROM};
	enum imgFlags{imgRelocsStripped=1,imgExecutable=2,imgLineNumsStripped=4,imgLocalSymsStripped=8,
		imgAggresiveWsTrim=0x10,imgLargeAddr=0x20};
	enum secFlags{secCode=0x20,secX=0x20000000,secR=0x40000000,secW=0x80000000};
	enum dllFlags{};
	
	struct mzH{
        u16 signature;
        u8 dosStub[0x3a];
        u32 peFileOffset;
    };mzH *mz;

    struct coffH
    {
    	u32 signature;
    	u16 machineType,
    		nOfSections;
    	u32 timeStamp,	
    		//0 - depredecated
    		coffSymbTableFileOff,
    		nOfSymbols;
    	u16 sizeOfOptionalHeader,
    		flags;
    };coffH *coff;

    struct opH64
    {
    	u16 signature;
    	u8 majorLinkerVer,
    		minorLinkerVer;
    	u32 codeSize,
    		initDataSize,
    		nonInitDataSize,
    		addrOfEntryPoint,
    		baseOfCode;
    	u64 imageBase;
    	u32 sectionAlignment,
    		fileAligment;
    	u16 majorOSVer,
    		minorOsVer,
    		majorImageVer,
    		minorImageVer,
    		majorSubsystemVer,
    		minorSubsystemVer;
    	u32 win32VersionValue,//reserved
    		imageSize,
    		headersSize,
    		checkSum;
    	u16 subSystem,
    		dllFlags;
    	u64 sizeOfStackReserve,
    		sizeOfStackCommit,
    		sizeOfHeapReserve,
    		sizeOfHeapCommit;
    	u32 loaderFlagsReserved,
    		nOfRvaAndSizes;
    	u64 exportTable,
    		importTable,
    		resourceTable,
    		exceptionTable,
    		certificateTable,
    		baseRelocationTable,
    		debug,
    		archTypeReserved,
    		globalPtr,
    		threadLocalStorageTable,
    		loadConfigTable,
    		boundTable,
    		importAddressTable,
    		delayImportDescriptor,
    		clrHeader,
    		reserved;//0
    };opH64 *op;
    
    struct secH
    {
    	u64 name;
    	u32 virtualSize,
    		virtualAddr,
    		rawDataSize,
    		rawDataOff,
    		relocationsOff,
    		lineNumbersOff;
    	u16	nOfRelocations,
    		nOfLinenumbers;
    	u32	secFlags;

    };secH *sec;

    void init(u8 *p, u32 len, u16 machineType, u16 subSystem, u32 rawDataOff, u32 flags, u32 secFlags){

    	mz=(mzH*)p;
	    mz->signature=0x5a4d;
	    mz->peFileOffset=0x80;

	    coff=(coffH*)(p+mz->peFileOffset);
	    coff->signature=0x4550;
	    coff->machineType=machineType;
	    coff->nOfSections=1;
	    //...
	    coff->sizeOfOptionalHeader=sizeof(*op);
	    coff->flags=flags;
	    
	    op=(opH64*)(p+mz->peFileOffset+0x18);
	    op->signature=pe32plus;
	    op->majorLinkerVer=1;
	    op->minorLinkerVer=73;
	    //...
	    op->codeSize=len;
	    op->initDataSize=op->codeSize+len;
	    op->addrOfEntryPoint=0x1000;
	    op->baseOfCode=0x1000;
	    op->imageBase=0x400000;
	    op->sectionAlignment=0x1000;
	    op->fileAligment=0x200;//2^n <= sectionAlignment, n=(9;16)
	    op->majorOSVer=1;
	    op->majorSubsystemVer=5;

	    op->imageSize=op->sectionAlignment+(op->baseOfCode)
	    &(~(op->sectionAlignment^(op->sectionAlignment-1))>>1);
	    //op->imageSize=0x4000;
	    op->headersSize=op->fileAligment+(sizeof(mzH)+sizeof(coffH)+sizeof(opH64))&~(op->fileAligment-1);
	    op->subSystem=subSystem;
	    op->sizeOfStackReserve=0x1000;
	    op->sizeOfStackCommit=0x1000;
	    op->sizeOfHeapReserve=0x10000;
	    op->sizeOfHeapCommit=0;
	    op->nOfRvaAndSizes=0x10;

	    sec=(secH*)(p+mz->peFileOffset+0x18+sizeof(opH64));
	    sec->name=0x65646f632e;
	    
	    sec->virtualSize=len;
	    sec->virtualAddr=0x1000;
	    sec->rawDataSize=len;
	    sec->rawDataOff=rawDataOff;
	    sec->secFlags=secFlags;
	}
};
