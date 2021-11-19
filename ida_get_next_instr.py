def get_next_instruction_address():
	current_instr = get_screen_ea()
	while current_instr < 0x10027FFF:
		esp = current_instr + 5
		offset_val = idaapi.get_dword(esp)
		return_addr = (esp + offset_val) & 0xFFFFFFFF
		set_cmt(current_instr, hex(return_addr), 0)
		next_call = ida_search.find_binary(return_addr, return_addr+0x10, "E8", 16, ida_search.SEARCH_DOWN)
		if next_call != ida_idaapi.BADADDR:			
			current_instr = next_call
		else:
			return
