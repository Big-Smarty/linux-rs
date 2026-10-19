/* SPDX-License-Identifier: GPL-2.0-only */
OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

PHDRS {
    text PT_LOAD FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    data PT_LOAD FLAGS(6);
    stack PT_GNU_STACK FLAGS(6);
}

SECTIONS {
    . = 0xffffffff80000000;
    __kernel_start = .;
    __text_start = .;
    .text : { *(.text .text.*) } :text
    . = ALIGN(4096);
    __text_end = .;
    __rodata_start = .;
    .rodata : { *(.rodata .rodata.*) } :rodata
    . = ALIGN(4096);
    __rodata_end = .;
    __data_start = .;
    .data : {
        KEEP(*(.limine_requests_start))
        KEEP(*(.limine_requests))
        KEEP(*(.limine_requests_end))
        *(.data .data.*)
        *(.got .got.*)
    } :data
    .bss : { *(.bss .bss.*) *(COMMON) } :data
    . = ALIGN(4096);
    __kernel_end = .;
    /DISCARD/ : { *(.eh_frame*) *(.comment*) *(.note*) }
}
ASSERT(__kernel_end < 0xffffffffc0000000, "kernel exceeds initial 1 GiB window")
ASSERT((__text_start & 4095) == 0, "text alignment")
ASSERT((__rodata_start & 4095) == 0, "rodata alignment")
ASSERT((__data_start & 4095) == 0, "data alignment")
