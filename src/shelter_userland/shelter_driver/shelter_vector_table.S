.text
.global shelter_vector_table
.globl shelter_vector_end
.balign 2048

shelter_vector_table:
//Current EL with SP_EL0
    b .
.balign 0x80
    b .
.balign 0x80
    b .
.balign 0x80
    b .

//Current EL with SP_EL1
.balign 0x80
    b .
.balign 0x80
    b .
.balign 0x80
    b .
.balign 0x80
    b .

//Lower EL with SP_EL1 from aarch64 exception
.balign 0x80
    b shelter_exit_sync
.balign 0x80
    b shelter_exit_irq
.balign 0x80
    b shelter_exit_fiq
.balign 0x80
    b shelter_exit_error

//Lower EL with SP_EL1 from aarch32 exception
.balign 0x80
    b .
.balign 0x80
    b .
.balign 0x80
    b .
.balign 0x80
    b .

.align	6

//os_enter
shelter_exit_sync:
	mov		x14, xzr
	mov		x13, x0
	mov     x0, #0x80000000                      
    add     x0, x0,#0xF00
    smc     #0

shelter_exit_irq:
	mov		x14, 0x80
	mov		x13, x0
	mov     x0, #0x80000000                      
    add     x0, x0,#0xF00
    smc     #0

shelter_exit_fiq:
	mov		x14, 0x100
	mov		x13, x0
	mov     x0, #0x80000000                      
    add     x0, x0,#0xF00
    smc     #0

shelter_exit_error:
	mov		x14, 0x180
	mov		x13, x0
	mov     x0, #0x80000000                      
    add     x0, x0,#0xF00
    smc     #0

shelter_vector_end:

