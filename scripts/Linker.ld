LINK_BASE = 0x0000;

ENTRY(Entry)

SECTIONS
{
    . = LINK_BASE;
    .text : {
        . = LINK_BASE;
        *(.text$ENTRY);
        *(.text$INIT);
        *(.text$CORE);
        *(.rdata*);
        FILL(0x00)
        . = ALIGN(0x1000);
        *(.text$END);
    }

    .eh_frame : {
        *( .eh_frame )
    }
}
