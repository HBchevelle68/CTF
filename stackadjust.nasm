BITS 32
segment .text ; use this if NX is on


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




GLOBAL _findMe@0
_findMe@0:
_findMe:

	
	; Get end address
	xor eax, eax
	add eax, 8
	mov esi, [fs:eax]

    ; Get Stack Base
	xor eax, eax
	add eax, 4
	mov edi, [fs:eax]

	mov DWORD ebx, 0xffbfdc5e
	xor ebx, 0xffffffff

	search:
		sub edi, 4   ;; increment otherwise
		cmp [edi], ebx ;; compare to desired eip address
		je .done	 ;; jump if done
		cmp esi, edi ;; compare to beginning of stack
		je .error
		jmp search

	.done:
		;db 0xcc
		add edi, -0x4
		mov esp, edi
		xor eax, eax
		pop ebp

		xor eax, eax
	.error:
		;db 0xcc

		mov esp, ebp

	ret
