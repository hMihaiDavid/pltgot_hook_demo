void _target_dump_imports_old(TARGET *target)
{	
	// First 3 entries are reserved. See SysV amd64 ABI supplement.
	Elf64_Addr *p = target->plt_got+3;
	size_t n = (target->plt_gotsz/sizeof(Elf64_Addr))-3;
	for(size_t i=0; i<n; i++, p++) {
		Elf64_Addr jmpaddr = *p;
		void *slot_address = (void*)(((size_t)target->plt_got_address)+((size_t)p - (size_t)target->plt_got));
		
		ssize_t symindex = -1; // TODO: Use an invalid index as specified in the docs.
		
		// Find the symbol table index for the current pltgot entry.
		for(size_t ri=0; ri < target->numrelocs; ri++) {
			Elf64_Addr r_offset; void *fixaddr;
			uint64_t r_info;
			if(target->pltreltype == DT_REL) {
				r_offset = target->u1.pltreltable[ri].r_offset;
				r_info = target->u1.pltreltable[ri].r_info;
			} else if(target->pltreltype == DT_RELA) {
				r_offset = target->u1.pltrelatable[ri].r_offset;
				r_info = target->u1.pltrelatable[ri].r_info;
			}

			fixaddr = (void *)r_offset;
			if(target->header.e_type == ET_DYN) // the binary is pie so va is relative.
				fixaddr = (void*)((size_t)fixaddr+(size_t)target->base_address);

			if(fixaddr == slot_address) symindex = ELF64_R_SYM(r_info);
		}
		if(symindex < 0) {
			fprintf(stderr, "[%lu] %p:\t%p\t(sym. #?)\tCANNOT FIND SIMBOL\n", i, slot_address, (void*)jmpaddr);
		} else {
			const char *symname = target_get_symbol_name(target, symindex);
			char *info_str = is_address_in_target(target, (void*)jmpaddr) ? " (not resolved)" : "";
			
			fprintf(stderr, "[%lu] %p:\t%p\t(sym. #%ld)\t%s%s <%p>\n", i, slot_address, (void*)jmpaddr, 
							symindex, symname, info_str, target_find_base(target, (void*)jmpaddr) );
		}
	}
	
}
