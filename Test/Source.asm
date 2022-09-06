extern MessageBoxW: proc
extern _ui64tow: proc

.data
	retstr dw 0
	spaces dw 000Ah, 000Bh, 000Ch,000Dh, 0085h, 2028h, 2029h, 0009h, 0020h, 00A0h, 1680h, 180Eh, 2000h, 2001h, 2002h, 2003h, 2004h, 2005h, 2006h, 2007h, 2008h, 2009h, 200Ah, 200Bh, 202Fh, 205Fh, 3000h, 0FEFFh, 0000h

.code
	
	public find
	public wslen
	public wsubs
	public left
	public right
	public comp
	public space
	public conc
	public ltrim

	ltrim proc

		xor r11, r11

		mov r13, rcx

		do:
			mov cx, [r13 + 2 * r11]
			call space
			test rax, rax
			jz next

			inc r11
			jmp do

		next:
			lea r14, [r13 + 2 * r11]
			xor r11, r11
			lea rax, retstr

		do2:
			mov r12w, [r14 + 2 * r11]
			mov [rax + 2 * r11], r12w
			test r12w, r12w
			jz lret

			inc r11
			jmp do2

		lret:
			mov rcx, r13
			ret

	ltrim endp

	conc proc

		xor r11, r11
		lea rax, retstr

		do:
			mov r10w, [rcx + 2 * r11]
			test r10w, r10w
			jz endstr

			mov [rax + 2 * r11], r10w
			lea rbx, [rax + 2 * r11]

			inc r11
			jmp do

		endstr:
			xor r11, r11
			inc rbx
			inc rbx
			
		do2:	
			mov r10w, [rdx + 2 * r11]
			mov [rbx + 2 * r11], r10w

			test r10w, r10w
			jz lret

			inc r11
			jmp do2

		lret:
			ret

	conc endp

	space proc

		mov bx, cx

		lea rcx, spaces
		mov dx, bx

		call find
		inc rax

		mov cx, bx

		ret

	space endp

	find proc

		xor rax, rax

		do:
			mov r10w, [rcx + 2 * rax]
			test r10w, r10w
			jz endstr

			cmp r10w, dx
			je lret

			inc rax
			jmp do

		endstr:
			or rax, 0FFFFFFFFFFFFFFFFh

		lret:
			ret

	find endp

	wslen proc

		xor rax, rax

		do:
			mov r10w, [rcx + 2 * rax]
			test r10w, r10w
			jz lret

			inc rax
			jmp do

		lret:
			ret

	wslen endp

	wsubs0 proc

		do:
			mov bx, [r10 + 2 * r11]	
			mov [retstr + 2 * r11], bx
			
			test bx, bx
			jz lret

			inc r11
			jmp do

		lret:
			ret

	wsubs0 endp

	wsubs1 proc

		mov rax, r8
		sub rax, 1

		do:
			mov bx, [r10 + 2 * r11]	
			mov [retstr + 2 * r11], bx
			
			test bx, bx
			jz lret

			cmp rax, r11
			je lret

			inc r11
			jmp do

		lret:
			ret

	wsubs1 endp

	wsubs proc

		xor r11, r11

		mov r10, rcx
		add r10, rdx
		add r10, rdx

		test r8, r8
		jne l1

		call wsubs0
		jmp lret

		l1:
			call wsubs1

		lret:
			lea rax, retstr
			ret

	wsubs endp

	left proc

		test rdx, rdx
		jz lret

		mov rbx, rdx
		
		mov r8, rdx
		xor rdx, rdx

		call wsubs

		mov rdx, rbx

		lret:
			ret

	left endp

	right proc

		test rdx, rdx
		jz lret

		call wslen

		test rax, rax
		jz lret
		
		mov rbx, rdx
		
		sub rax, rdx
		mov rdx, rax
		xor r8, r8

		call wsubs

		mov rdx, rbx

		lret:
			ret

	right endp

	comp proc

		xor rax, rax

		do:
			mov r10w, [rcx + 2 * rax]
			
			cmp r10w, [rdx + 2 * rax]
			jne fail

			test r10w, r10w
			jz success

			inc rax
			jmp do

		fail:
			xor rax, rax
			jmp lret

		success:
			or al, 1

		lret:
			ret

	comp endp

end
