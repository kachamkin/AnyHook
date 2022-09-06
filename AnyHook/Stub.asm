.code

StealthStub_ASM_x64 proc
	
	sub			rsp, 8 * 4
	
; save stack before call to CreateThread
	mov			r10, qword ptr [rsp + 40]
	mov			qword ptr [rbx + 64 + 8 * 19], r10
	mov			r10, qword ptr [rsp + 32]
	mov			qword ptr [rbx + 64 + 8 * 18], r10

; CreateThread
	mov			qword ptr [rsp + 40], 0
	mov			qword ptr [rsp + 32], 0
	mov			r9, qword ptr [rbx + 16]	; RemoteThreadParam
	mov			r8, qword ptr [rbx + 8]		; RemoteThreadStart
	xor			rdx, rdx
	xor			rcx, rcx
	call		qword ptr [rbx]				; CreateThread
	mov			qword ptr [rbx + 56], rax	; return thread handle

; restore stack after call to CreateThread
	mov			rdx, rsp
	add			rdx, 32
	mov			rcx, qword ptr [rbx + 64 + 8 * 18]
	mov			qword ptr [rdx], rcx
	add			rdx, 8
	mov			rcx, qword ptr [rbx + 64 + 8 * 19]
	mov			qword ptr [rdx], rcx

; wait for thread completion
	mov			rdx, -1
	mov			rcx, rax
	mov			r11, rax
	call		qword ptr [rbx + 24]		; WaitForSingleObject

; close thread handle	
	mov			rcx, r11		
	call		qword ptr [rbx + 40]		; CloseHandle

; signal to hooking process: thread completed	
	mov			rcx, qword ptr [rbx + 48]		
	call		qword ptr [rbx + 32]		; SetEvent

; close signal handle	
	mov			rcx, qword ptr [rbx + 48]		
	call		qword ptr [rbx + 40]		; CloseHandle

; restore context
	mov			rax, [rbx + 64 + 8 * 0]
	mov			rcx, [rbx + 64 + 8 * 1]
	mov			rdx, [rbx + 64 + 8 * 2]
	mov			rbp, [rbx + 64 + 8 * 3]
	mov			rsp, [rbx + 64 + 8 * 4]
	mov			rsi, [rbx + 64 + 8 * 5]
	mov			rdi, [rbx + 64 + 8 * 6]
	mov			r8,  [rbx + 64 + 8 * 10]
	mov			r9,  [rbx + 64 + 8 * 11]
	mov			r10, [rbx + 64 + 8 * 12]
	mov			r11, [rbx + 64 + 8 * 13]
	mov			r12, [rbx + 64 + 8 * 14]
	mov			r13, [rbx + 64 + 8 * 15]
	mov			r14, [rbx + 64 + 8 * 16]
	mov			r15, [rbx + 64 + 8 * 17]
	push		qword ptr [rbx + 64 + 8 * 9]	; push RFlags	
	push		qword ptr [rbx + 64 + 8 * 8]	; save old RIP
	mov			rbx, [rbx + 64 + 8 * 7]
	
	add			rsp, 8
	popfq

; continue execution...
	jmp			qword ptr [rsp - 16]	
	
; outro signature, to automatically determine code size
	db 78h
	db 56h
	db 34h
	db 12h

StealthStub_ASM_x64 endp

end