global _start
_start:

mov  al, 1   ; write syscall
mov dil, al  ; write to stdout
mov esi, msg ; write from msg buffer
mov  dl, 14  ; write 14 bytes from msg buffer
syscall
; We use the smallest registers possible to reduce instruction sizes.

mov  al, 1   ; exit syscall using 32-bit number = 1. di==1 from earlier
int 0x80
; Using the 64-bit "syscall" instruction would require rax==60 which would
; require a larger instruction. Additionally, 32-bit uses ebx for the exit
; code. This will likely be zero because we don't use it anywhere else
; meaning that we will likely get a 0 exit code with having to explicitly
; zero ebx; if we don't get exitcode==0 it's fine because we've printed
; the message but I have not observed that yet.

msg db "Hello, World!", 0Ah

