# pltgot
Linux x86_64 PLT hooking. Examine and hook a live process library imports.

I wrote this some years ago and haven't tested it since then. I'm dumping it now cause someone might find it useful.

given a live linux process this tools allows you to dump it's plt table (library imports) and
to hook them. It injects a shellcode of your chosing in the target's executable memory and
patches specified .plt.got entries to point to your shellcode, which can return to the original if wanted.

It doesn't rely on any section information, only the program header table and the dynamic segment (PT_DYNAMIC: 
info embeded into the elf to be used by the dynamic loader, pointed by a ph entry). All this info is required per standard to be in memory.
for dynamic linking to work.
Because of this it works with strip'ed and sstrip'ed binaries (strip'ed binaries still leaves useful section info, whereas sstrip by ElfKickers doesn't).

the place the shellcode is injected is at the gap at the end of the code segment of the library whose entry is being hooked.
there may not be a gap, in which case it fails. All library functions hooked will execute the same shellcode if they are from
the same library.
This code is a demo to show how to find dynamic loader info and plt table of a remote running process and how to r/w mem.
If you want a bigger shellcode you could write a 1st stage sc that mmap's a bigger region idk.


you can find useful info about ELF here
https://github.com/hjl-tools/x86-psABI/wiki/X86-psABI
particularly "The x86-64 psABI version 1.0"
