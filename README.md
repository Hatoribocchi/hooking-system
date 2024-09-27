```
void ExampleUsage()
{
    uintptr_t OriginalFunction = 0x12345678;
    uintptr_t NewFunction = 0x87654321;
    AddHook(OriginalFunction, NewFunction);

    uint32_t VTableIndex = 1;
    uintptr_t Entity = 0x11223344;
    AddHook(OriginalFunction, NewFunction, true, VTableIndex, Entity);

    ApplyHooks();
}
```
