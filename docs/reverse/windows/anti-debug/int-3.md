[EN](./int-3.md) | [ZH](./int-3-zh.md)
Whenever a software interrupt exception is triggered, the exception address and the value of the EIP register will point to the next instruction that generated the exception. But the breakpoint exception is one of the special cases.


When the `EXCEPTION_BREAKPOINT(0x80000003)` exception is triggered, Windows will assume that this is caused by a single-byte &quot;`CC`&quot; opcode (that is, the `Int 3` instruction). Windows decrements the exception address to point to the asserted &quot; `CC`&quot; opcode, then pass the exception to the exception handler. But the value of the EIP register does not change.


Therefore, if `CD 03` is used (this is the machine code representation of `Int 03`), then when the exception handling handle accepts control, the exception address is the location pointing to `03`.