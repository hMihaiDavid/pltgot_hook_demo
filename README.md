# pltgot
Linux x86_64 PLT hooking. Examine and hook a live process library imports.

I wrote this some years ago and haven't tested it since then. I'm dumping it now cause I just found it and someone might find it useful.

given a live linux process this tools allows you to dump it's plt table (library imports) and
to hook them. It injects a shellcode of your chosing in the target's executable memory and
patches specified .plt.got entries to point to your shellcode, which can return to the original if wanted.

It doesn't rely on any section information, only the program header table and the dynamic segment (PT_DYNAMIC: 
info embeded into the elf to be used by the dynamic loader, pointed by a ph entry). All this info is required per standard to be in memory for dynamic linking to work.
Because of this it works with strip'ed and sstrip'ed binaries (strip'ed binaries still leaves useful section info, whereas sstrip by ElfKickers doesn't).
T
he downside is we use little hacks to calculate some values, since they are not present in PT_DYNAMIC.
the number of pltgot entries is calculated from the number of dynamic relocation entries (DT_PLTREL) since these should
be equal (?). It is. :)
the size of the dynamic symbol table id calculated from the hash table since standard says:
"The number of symbol table entries should equal nchain (in hash table)"
if hash table is not present, it is observed that default linker scripts put the dynamic string table right after the dynamic
symbol table so we calculate the symbol table's size by substracting the two pointers. The address of dynamic string table
is found in the dynamic segment.


the place the shellcode is injected is at the gap at the end of the code segment of the library whose entry is being hooked.
there may not be a gap, in which case it fails. All library functions hooked will execute the same shellcode if they are from
the same library.
This code is a demo to show how to find dynamic loader info and plt table of a remote running process and how to r/w mem.
If you want a bigger shellcode you could write a 1st stage sc that mmap's a bigger region idk.


you can find useful info about ELF here
https://github.com/hjl-tools/x86-psABI/wiki/X86-psABI
particularly "The x86-64 psABI version 1.0"
