.code

asm_sgdt proc
	sgdt    fword ptr [rcx]
	ret
asm_sgdt endp

vm_detect proc
    mov rcx, 01D9h
    xor rdx, rdx
    wrmsr
    rdmsr
    shl rdx, 20h	; EDX:EAX for wrmsr
    or rax, rdx
    jmp check_msr

check_msr:
    test al, 1
    jnz no_detect
    mov al, 1
    ret
    
no_detect:
    xor rax, rax
    xor rdx, rdx
    mov rdx, 01D9h
    wrmsr
    ret
vm_detect endp

asm_pg_single_step1 proc
    pushfq
    mov rax,0
    or dword ptr [rsp], 0100h
    mov eax, 0FFFFFFFFh
    popfq
    mov rax,1 ;如果在虚拟机里面,这句话是触发不了的
    nop
    ret
asm_pg_single_step1 endp

asm_pg_single_step proc
    pushfq
    or dword ptr [rsp], 0100h
    mov eax, 0FFFFFFFFh
    popfq
    mov rax, 1
    nop
    ret
asm_pg_single_step endp

asm_pg_KiErrata361Present proc
    mov ax,ss
    pushfq
    or qword ptr[rsp],100h
    popfq
    mov ss,ax
    db 0f1h ;icebp
    pushfq
    and qword ptr[rsp],0FFFFFEFFh
    popfq
    ret
asm_pg_KiErrata361Present endp

asm_xbegin proc
    xbegin $begin1
    xend

$begin1:
    ret
asm_xbegin endp

end