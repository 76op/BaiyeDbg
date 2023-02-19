.code

; defined in guest-context.h
guest_context struct
  ; general-purpose registers
  $rax qword ?
  $rcx qword ?
  $rdx qword ?
  $rbx qword ?
  qword ? ; padding
  $rbp qword ?
  $rsi qword ?
  $rdi qword ?
  $r8  qword ?
  $r9  qword ?
  $r10 qword ?
  $r11 qword ?
  $r12 qword ?
  $r13 qword ?
  $r14 qword ?
  $r15 qword ?

  ; control registers
  $cr2 qword ?
  $cr8 qword ?

  ; debug registers
  $dr0 qword ?
  $dr1 qword ?
  $dr2 qword ?
  $dr3 qword ?
  $dr6 qword ?
guest_context ends

extern ?handle_vm_exit@hv@@YA_NQEAUguest_context@1@@Z : proc

; execution starts here after a vm-exit
?vm_exit@hv@@YAXXZ proc
  ; allocate space on the stack to store the guest context
  sub rsp, 0C0h

  ; general-purpose registers
  mov guest_context.$rax[rsp], rax
  mov guest_context.$rcx[rsp], rcx
  mov guest_context.$rdx[rsp], rdx
  mov guest_context.$rbx[rsp], rbx
  mov guest_context.$rbp[rsp], rbp
  mov guest_context.$rsi[rsp], rsi
  mov guest_context.$rdi[rsp], rdi
  mov guest_context.$r8[rsp],  r8
  mov guest_context.$r9[rsp],  r9
  mov guest_context.$r10[rsp], r10
  mov guest_context.$r11[rsp], r11
  mov guest_context.$r12[rsp], r12
  mov guest_context.$r13[rsp], r13
  mov guest_context.$r14[rsp], r14
  mov guest_context.$r15[rsp], r15

  ; control registers
  mov rax, cr2
  mov guest_context.$cr2[rsp], rax
  mov rax, cr8
  mov guest_context.$cr8[rsp], rax

  ; debug registers
  mov rax, dr0
  mov guest_context.$dr0[rsp], rax
  mov rax, dr1
  mov guest_context.$dr1[rsp], rax
  mov rax, dr2
  mov guest_context.$dr2[rsp], rax
  mov rax, dr3
  mov guest_context.$dr3[rsp], rax
  mov rax, dr6
  mov guest_context.$dr6[rsp], rax

  ; first argument is the guest context
  mov rcx, rsp

  ; call handle_vm_exit
  sub rsp, 28h
  call ?handle_vm_exit@hv@@YA_NQEAUguest_context@1@@Z
  add rsp, 28h

  ; handle_vm_exit returns true if we should stop virtualization
  mov r15, rax

  ; debug registers
  mov rax, guest_context.$dr0[rsp]
  mov dr0, rax
  mov rax, guest_context.$dr1[rsp]
  mov dr1, rax
  mov rax, guest_context.$dr2[rsp]
  mov dr2, rax
  mov rax, guest_context.$dr3[rsp]
  mov dr3, rax
  mov rax, guest_context.$dr6[rsp]
  mov dr6, rax

  ; control registers
  mov rax, guest_context.$cr2[rsp]
  mov cr2, rax
  mov rax, guest_context.$cr8[rsp]
  mov cr8, rax

  ; general-purpose registers
  mov rax, guest_context.$rax[rsp]
  mov rcx, guest_context.$rcx[rsp]
  mov rdx, guest_context.$rdx[rsp]
  mov rbx, guest_context.$rbx[rsp]
  mov rbp, guest_context.$rbp[rsp]
  mov rsi, guest_context.$rsi[rsp]
  mov rdi, guest_context.$rdi[rsp]
  mov r8,  guest_context.$r8[rsp]
  mov r9,  guest_context.$r9[rsp]
  mov r10, guest_context.$r10[rsp]
  mov r11, guest_context.$r11[rsp]
  mov r12, guest_context.$r12[rsp]
  mov r13, guest_context.$r13[rsp]
  mov r14, guest_context.$r14[rsp]

  test r15b, r15b
  mov r15, guest_context.$r15[rsp]
  jnz stop_virtualization

  ; if handle_exit returned false, perform a vm-enter as usual
  vmresume

stop_virtualization:
  ; we'll be dirtying these registers in order to setup the
  ; stack so we need to store and restore them before we can use them.
  ; also note that we're not allocating any stack space for the trap
  ; frame since we can just reuse the space allocated for the guest
  ; context.
  push rax
  push rdx
  push rbp
  lea rbp, [rsp + 38h]

  ; push SS
  mov rdx, 0804h; VMCS_GUEST_SS_SELECTOR
  vmread rax, rdx
  mov [rbp - 00h], rax

  ; push RSP
  mov rdx, 681Ch; VMCS_GUEST_RSP
  vmread rax, rdx
  mov [rbp - 08h], rax

  ; push RFLAGS
  mov rdx, 6820h; VMCS_GUEST_RFLAGS
  vmread rax, rdx
  mov [rbp - 10h], rax

  ; push CS
  mov rdx, 0802h; VMCS_GUEST_CS_SELECTOR
  vmread rax, rdx
  mov [rbp - 18h], rax

  ; push RIP
  mov rdx, 681Eh; VMCS_GUEST_RIP
  vmread rax, rdx
  mov [rbp - 20h], rax

  ; the C++ exit-handler needs to ensure that the control register shadows
  ; contain the current guest control register values (even the guest-owned
  ; bits!) before returning.

  ; store cr0 in rax
  mov rax, 6004h ; VMCS_CTRL_CR0_READ_SHADOW
  vmread rax, rax

  ; store cr4 in rdx
  mov rdx, 6006h ; VMCS_CTRL_CR4_READ_SHADOW
  vmread rdx, rdx

  ; execute vmxoff before we restore cr0 and cr4
  vmxoff

  ; restore cr0 and cr4
  mov cr0, rax
  mov cr4, rdx

  ; restore the dirty registers
  pop rbp
  pop rdx
  pop rax

  ; we use iretq in order to do the following all in one instruction:
  ;
  ;   pop RIP
  ;   pop CS
  ;   pop RFLAGS
  ;   pop RSP
  ;   pop SS
  ;
  iretq

?vm_exit@hv@@YAXXZ endp

end

