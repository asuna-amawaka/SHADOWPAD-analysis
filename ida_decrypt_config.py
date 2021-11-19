import binascii

def decode_string(ciphertext):
	output = bytearray()
	acc = (ciphertext[0] + (ciphertext[1] << 0x8)) & 0xFFFF
	for c in ciphertext[4:]:
		tmp = (acc + acc) & 0xFFFFFFFF
		acc = acc + (tmp * 8) + 0x107E666D
		key = (((acc >> 0x18) & 0xFF) + ((acc >> 0x10) & 0xFF) + ((acc >> 0x8) & 0xFF) + (acc & 0xFF)) & 0xFF	
		res = (c ^ key) & 0xFF
		output.append(res)
	h_res = "".join(["{:02x}".format(x) for x in output])
	return binascii.unhexlify(h_res).decode('utf-8')
	
	
def get_config_string():
	ea = get_screen_ea()
	eof = ida_ida.inf_get_max_ea()
	with open("decoded_config", "w", encoding="utf-8") as outfile:
		while ea < eof:	
			max_str_len = idaapi.get_word(ea+2) + 4
			ciphertext = bytearray(get_bytes(ea, max_str_len))
			result = decode_staticstring(ciphertext)
			set_cmt(ea, result, 0)
			print(result)
			outfile.write(result)
			outfile.write("=====\n")
			ea += max_str_len		
