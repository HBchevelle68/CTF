; The order of registers on the stack for pushad/popad
struc PUSHAD_DATA
	.edi	resd 1
	.esi	resd 1
	.ebp	resd 1
	.esp	resd 1
	.ebx	resd 1
	.edx	resd 1
	.ecx	resd 1
	.eax	resd 1
endstruc

;Linked list entry
struc LIST_ENTRY
	.Flink		resd 1
	.Blink		resd 1
endstruc

;Most of the PEB structure
struc PEB
	.InheritedAddressSpace				resb 1
	.ReadImageFileExecOptions			resb 1
	.BeingDebugged						resb 1
	.SpareBool							resb 1
	.Mutant								resd 1
	.ImageBaseAddress					resd 1
	.Ldr								resd 1	; PEB_LDR_DATA*
	.ProcessParameters					resd 1
	.SubSystemData						resd 1
	.ProcessHeap						resd 1
	.FastPebLock						resd 1
	.FastPebLockRoutine					resd 1
	.FastPebUnlockRoutine				resd 1
	.EnvironmentUpdateCount				resd 1
	.KernelCallbackTable				resd 1
	.SystemReserved						resd 1
	.AtlThunkSListPtr32					resd 1
	.FreeList							resd 1
	.TlsExpansionCounter				resd 1
	.TlsBitmap							resd 1
	.TlsBitmapBits						resd 2
	.ReadOnlySharedMemoryBase			resd 1
	.ReadOnlySharedMemoryHeap			resd 1
	.ReadOnlyStaticServerData			resd 1
	.AnsiCodePageData					resd 1
	.OemCodePageData					resd 1
	.UnicodeCaseTableData				resd 1
	.NumberOfProcessors					resd 1
	.NtGlobalFlag						resd 1
	.CriticalSectionTimeout				resd 2
	.HeapSegmentReserve					resd 1
	.HeapSegmentCommit					resd 1
	.HeapDeCommitTotalFreeThreshold		resd 1
	.HeapDeCommitFreeBlockThreshold		resd 1
	.NumberOfHeaps						resd 1
	.MaximumNumberOfHeaps				resd 1
	.ProcessHeaps						resd 1
	.GdiSharedHandleTable				resd 1
	.ProcessStarterHelper				resd 1
	;...
endstruc

struc EXCEPTION_REGISTRATION_RECORD
	.Next								resd 1
	.Handler							resd 1
endstruc


struc TEB ;located at fs:[0]

	.NtTib.ExceptionList				resd 1
	.NtTib.StackBase					resd 1
	.NtTib.StackLimit					resd 1
	.NtTib.SubSystemTib					resd 1
	.NtTib.FiberData					resd 0 ;union with version
	.NtTib.Version						resd 1
	.NtTib.ArbitraryUserPointer			resd 1
	.NtTib.Self							resd 1
	.EnvironmentPointer					resd 1
	.ClientId.UniqueProcess				resd 1
	.ClientId.UniqueThread				resd 1
	.ActiveRpcHandle					resd 1
	.ThreadLocalStoragePointer			resd 1
	.ProcessEnvironmentBlock			resd 1
	.LastErrorValue						resd 1
	.CountOfOwnedCriticalSections		resd 1
	.CsrClientThread					resd 1
	.Win32ThreadInfo					resd 1
	;...
endstruc

struc PEB_LDR_DATA
	.Length								resd 1; ULONG //00
	.Initialized						resd 1; BOOL //04
	.SsHandle							resd 1; PVOID //08
	.InLoadOrderModuleList.Flink		resd 1; LIST_ENTRY //0C
	.InLoadOrderModuleList.Blink		resd 1; LIST_ENTRY
	.InMemoryOrderModuleList.Flink		resd 1; LIST_ENTRY
	.InMemoryOrderModuleList.Blink			resd 1; LIST_ENTRY
	.InInitializationOrderModuleList.Flink	resd 1; LIST_ENTRY
	.InInitializationOrderModuleList.Blink	resd 1; LIST_ENTRY
endstruc

; The following structure is from Microsoft public symbols for Windows XP. It was extended in later versions of Windows and now (Windows 8) has nearly twice as many fields. However, for a barebones loader, the old structure suffices.
; typedef struct _LDR_MODULE {
; 	LIST_ENTRY InLoadOrderModuleList; 
; 	LIST_ENTRY InMemoryOrderModuleList; 
; 	LIST_ENTRY InInitializationOrderModuleList; 
; 	PVOID BaseAddress; 
;	PVOID EntryPoint; 
; 	ULONG SizeOfImage; 
; 	UNICODE_STRING FullDllName; 
; 	UNICODE_STRING BaseDllName; 
; 	ULONG Flags; 
; 	SHORT LoadCount; 
; 	SHORT TlsIndex; 
; 	LIST_ENTRY HashTableEntry; 
; 	ULONG TimeDateStamp;
; } LDR_MODULE, *PLDR_MODULE;
struc LDR_MODULE
	.InLoadOrderModuleList.Flink           resd 1
	.InLoadOrderModuleList.Blink           resd 1
	.InMemoryOrderModuleList.Flink         resd 1
	.InMemoryOrderModuleList.Blink         resd 1
	.InInitializationOrderModuleList.Flink resd 1
	.InInitializationOrderModuleList.Blink resd 1
	.BaseAddress                           resd 1
	.EntryPoint                            resd 1
	.SizeOfImage                           resd 1
	;... for a barebones loader, we do not need the other fields
endstruc


struc IMAGE_DOS_HEADER
	.e_magic					resw 1  ; Magic number
	.e_cblp						resw 1  ; Bytes on last page of file
	.e_cp						resw 1  ; Pages in file
	.e_crlc						resw 1  ; Relocations
	.e_cparhdr					resw 1  ; Size of header in paragraphs
	.e_minalloc					resw 1  ; Minimum extra paragraphs needed
	.e_maxalloc					resw 1  ; Maximum extra paragraphs needed
	.e_ss						resw 1  ; Initial (relative) SS value
	.e_sp						resw 1  ; Initial SP value
	.e_csum						resw 1  ; Checksum
	.e_ip						resw 1  ; Initial IP value
	.e_cs						resw 1  ; Initial (relative) CS value
	.e_lfarlc					resw 1  ; File address of relocation table
	.e_ovno						resw 1  ; Overlay number
	.e_res						resw 4  ;                    // Reserved words
	.e_oemid					resw 1  ; OEM identifier (for e_oeminfo)
	.e_oeminfo					resw 1  ; OEM information; e_oemid specific
	.e_res2						resw 10 ;                  // Reserved words
	.e_lfanew					resd 1  ; File address of new exe header
endstruc

struc IMAGE_FILE_HEADER
	.Machine				resw 1
	.NumberOfSections		resw 1
	.TimeDateStamp			resd 1
	.PointerToSymbolTable	resd 1
	.NumberOfSymbols		resd 1
	.SizeOfOptionalHeader	resw 1
	.Characteristics		resw 1
endstruc

struc IMAGE_OPTIONAL_HEADER
	.Magic						resw 1
	.MajorLinkerVersion			resb 1
	.MinorLinkerVersion			resb 1
	.SizeOfCode					resd 1
	.SizeOfInitializedData		resd 1
	.SizeOfUninitializedData	resd 1
	.AddressOfEntryPoint		resd 1
	.BaseOfCode					resd 1
	.BaseOfData					resd 1
	.ImageBase					resd 1
	.SectionAlignment			resd 1
	.FileAlignment				resd 1
	.MajorOperatingSystemVersion	resw 1
	.MinorOperatingSystemVersion	resw 1
	.MajorImageVersion			resw 1
	.MinorImageVersion			resw 1
	.MajorSubsystemVersion		resw 1
	.MinorSubsystemVersion		resw 1
	.Win32VersionValue			resd 1
	.SizeOfImage				resd 1
	.SizeOfHeaders				resd 1
	.CheckSum					resd 1
	.Subsystem					resw 1
	.DllCharacteristics			resw 1
	.SizeOfStackReserve			resd 1
	.SizeOfStackCommit			resd 1
	.SizeOfHeapReserve			resd 1
	.SizeOfHeapCommit			resd 1
	.LoaderFlags				resd 1
	.NumberOfRvaAndSizes		resd 1
	.DataDirectory.IMAGE_DIRECTORY_ENTRY_EXPORT.VirtualAddress			resd 1; Export Directory
	.DataDirectory.IMAGE_DIRECTORY_ENTRY_EXPORT.Size					resd 1
	.DataDirectory.IMAGE_DIRECTORY_ENTRY_IMPORT.VirtualAddress			resd 1; Import Directory
	.DataDirectory.IMAGE_DIRECTORY_ENTRY_IMPORT.Size					resd 1
	.DataDirectory.IMAGE_DIRECTORY_ENTRY_RESOURCE.VirtualAddress		resd 1; Resource Directory
	.DataDirectory.IMAGE_DIRECTORY_ENTRY_RESOURCE.Size					resd 1
	.DataDirectory.IMAGE_DIRECTORY_ENTRY_EXCEPTION.VirtualAddress		resd 1; Exception Directory
	.DataDirectory.IMAGE_DIRECTORY_ENTRY_EXCEPTION.Size					resd 1
	.DataDirectory.IMAGE_DIRECTORY_ENTRY_SECURITY.VirtualAddress		resd 1; Security Directory
	.DataDirectory.IMAGE_DIRECTORY_ENTRY_SECURITY.Size					resd 1
	.DataDirectory.IMAGE_DIRECTORY_ENTRY_BASERELOC.VirtualAddress		resd 1; Base Relocation Table
	.DataDirectory.IMAGE_DIRECTORY_ENTRY_BASERELOC.Size					resd 1
	.DataDirectory.IMAGE_DIRECTORY_ENTRY_DEBUG.VirtualAddress			resd 1; Debug Directory
	.DataDirectory.IMAGE_DIRECTORY_ENTRY_DEBUG.Size						resd 1
	.DataDirectory.IMAGE_DIRECTORY_ENTRY_ARCHITECTURE.VirtualAddress	resd 1; Architecture Specific Data
	.DataDirectory.IMAGE_DIRECTORY_ENTRY_ARCHITECTURE.Size				resd 1
	.DataDirectory.IMAGE_DIRECTORY_ENTRY_GLOBALPTR.VirtualAddress		resd 1; RVA of GP
	.DataDirectory.IMAGE_DIRECTORY_ENTRY_GLOBALPTR.Size					resd 1
	.DataDirectory.IMAGE_DIRECTORY_ENTRY_TLS.VirtualAddress				resd 1; TLS Directory
	.DataDirectory.IMAGE_DIRECTORY_ENTRY_TLS.Size						resd 1
	.DataDirectory.IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG.VirtualAddress		resd 1; Load Configuration Directory
	.DataDirectory.IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG.Size				resd 1
	.DataDirectory.IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT.VirtualAddress	resd 1; Bound Import Directory in headers
	.DataDirectory.IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT.Size				resd 1
	.DataDirectory.IMAGE_DIRECTORY_ENTRY_IAT.VirtualAddress				resd 1; Import Address Table
	.DataDirectory.IMAGE_DIRECTORY_ENTRY_IAT.Size						resd 1
	.DataDirectory.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT.VirtualAddress	resd 1; Delay Load Import Descriptors
	.DataDirectory.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT.Size				resd 1
	.DataDirectory.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR.VirtualAddress	resd 1; COM Runtime descriptor
	.DataDirectory.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR.Size			resd 1
endstruc

struc IMAGE_BASE_RELOCATION
    .VirtualAddress		resd 1
    .SizeOfBlock		resd 1
endstruc

IMAGE_REL_BASED_ABSOLUTE              equ	0
IMAGE_REL_BASED_HIGH                  equ	1
IMAGE_REL_BASED_LOW                   equ	2
IMAGE_REL_BASED_HIGHLOW               equ	3
IMAGE_REL_BASED_HIGHADJ               equ	4
IMAGE_REL_BASED_MIPS_JMPADDR          equ	5
IMAGE_REL_BASED_MIPS_JMPADDR16        equ	9
IMAGE_REL_BASED_IA64_IMM64            equ	9
IMAGE_REL_BASED_DIR64                 equ	10

struc IMAGE_SECTION_HEADER
    .Name					resb 8
    .VirtualSize			resd 1
    .VirtualAddress			resd 1
    .SizeOfRawData			resd 1
    .PointerToRawData		resd 1
    .PointerToRelocations	resd 1
    .PointerToLinenumbers	resd 1
    .NumberOfRelocations	resw 1
    .NumberOfLinenumbers	resw 1
    .Characteristics		resd 1
endstruc

struc IMAGE_IMPORT_DESCRIPTOR
	.OriginalFirstThunk	resd 1	; 0 for terminating null import descriptor, RVA to original unbound IAT (PIMAGE_THUNK_DATA)
	.TimeDateStamp		resd 1	; 0 if not bound,
								; -1 if bound, and real date\time stamp
                                ;    in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                ;    O.W. date/time stamp of DLL bound to (Old BIND)
	.ForwarderChain		resd 1  ; -1 if no forwarders
	.Name				resd 1
	.FirstThunk			resd 1  ; RVA to IAT (if bound this IAT has actual addresses)
endstruc

struc IMAGE_EXPORT_DIRECTORY
	.Characteristics					resd 1
	.TimeDateStamp						resd 1
	.MajorVersion						resw 1
	.MinorVersion						resw 1
	.Name							resd 1
	.Base							resd 1
	.NumberOfFunctions					resd 1
	.NumberOfNames						resd 1
	.AddressOfFunctions					resd 1
	.AddressOfNames						resd 1
	.AddressOfNameOrdinals				resd 1
endstruc

struc IMAGE_IMPORT_BY_NAME
    .Hint	resw 1
    .Name	resb 1 ; null terminated string
endstruc

;typedef struct _IMAGE_THUNK_DATA32 {
    ;union {
        ;DWORD ForwarderString;      // PBYTE
        ;DWORD Function;             // PDWORD
        ;DWORD Ordinal;
        ;DWORD AddressOfData;        // PIMAGE_IMPORT_BY_NAME
    ;} u1;
;} IMAGE_THUNK_DATA32;
;
;typedef struct _IMAGE_IMPORT_BY_NAME {
    ;WORD    Hint;
    ;BYTE    Name[1];
;} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
