; linker -> all options -> No (/SAFESEH:NO)

extern buf_64:QWORD
extern buf:QWORD

;uncomment for 32-bit binary
;extern _buf:DWORD
;.386
;.option model, c

.data

.code

no_ctx_switch PROC
;LOCAL buffer[400h]:DWORD
	;lea eax, buf
	
	push 2Bh
	;lea rax, buffer
	;the stack is not enough
	;mov rax, 10000D80h
	;push rax;stack
	push rsp
	push 046h
	push 33h
	;lea rax, exec
	mov rax, 10000000h
	push rax
	iretq
	ret
exec:
	lea rax, buf_64
	jmp rax

no_ctx_switch endp

ctx_switch_64to32 proc
	mov rcx, rsp
	mov dword ptr[rsp+16], 053h
	mov dword ptr[rsp+12], 10000800h
	mov dword ptr[rsp+8], 0046h
	mov dword ptr[rsp+4], 23h 
	mov dword ptr[rsp], 10000000h
	iretd
	call next
next:
	add dword ptr [rsp], 5h
ctx_switch_64to32 endp

ctx_switch_32to64_2 proc
	db 90h, 90h, 90h, 90h, 90h, 90h, 90h
	db 0eah, 012h, 00, 00, 10h, 33h, 00  	;jmp far 033h:10000012h
	db 90h, 90h, 90h, 90h, 90h, 90h, 90h
	mov rsp, rcx
	db 90h, 90h, 90h, 90h, 90h, 90h, 90h
	db 90h, 90h, 90h, 90h, 90h, 90h, 90h
	db 90h, 90h, 90h, 90h, 90h, 90h, 90h
	db 90h, 90h, 90h, 90h, 90h, 90h, 90h
ctx_switch_32to64_2  endp

ctx_switch_32to64 proc
	mov eax, 2Bh
	mov ss, eax
	nop
	db 6Ah, 2Bh ;push 2bh
	db 68h, 00, 08h, 00, 01; push 1000800
	db 68h, 46h, 00, 00, 00; push 46h
	db 6Ah, 33h ;push 33h
	;mov dword ptr[rsp+16], 02Bh
	;mov dword ptr[rsp+12], 10000800h
	;mov dword ptr[rsp+8], 0046h
	;mov dword ptr[rsp+4], 33h
	;mov dword ptr[rsp], 10000032h 
	db 0E8h, 00, 00, 00, 00; call next_instr
	db 83h, 04, 24h, 05h; 4 + size(iretd)
	iretd
	db 90h, 90h
	xor rax, rax
	mov rax, gs:[rax+8]
	shr rax, 32
	shl rax, 32
	or rax, rcx
	mov rsp, rax
	db 90h, 90h, 90h, 90h, 90h, 90h, 90h
	db 90h, 90h, 90h, 90h, 90h, 90h, 90h
	db 90h, 90h, 90h, 90h, 90h, 90h, 90h
	db 90h, 90h, 90h, 90h, 90h, 90h, 90h
	db 90h, 90h, 90h, 90h, 90h, 90h, 90h
	db 90h, 90h, 90h, 90h, 90h, 90h, 90h
	db 90h, 90h, 90h, 90h, 90h, 90h, 90h
ctx_switch_32to64 endp


spawn_calc_64 PROC
	lea rax, buf_64
	jmp rax
spawn_calc_64 endp

; execute from 32-bit binary the shellcode
spawn_calc_32 PROC
LOCAL buffer[200h]:DWORD
	;uncomment follow
	;jmp _buf
	ret
spawn_calc_32 endp

end