import sys
import binascii
import struct

def decrypt_strings(ciphertext):
	output = bytearray()
	acc = (ciphertext[0] + (ciphertext[1] << 0x8)) & 0xFFFF
	for c in ciphertext[4:]:
		tmp = (acc + acc) & 0xFFFFFFFF
		acc = acc + (tmp * 8) + 0x107E666D
		acc &= 0xFFFFFFFF
		key = (((acc >> 0x18) & 0xFF) + ((acc >> 0x10) & 0xFF) + ((acc >> 0x8) & 0xFF) + (acc & 0xFF)) & 0xFF	
		res = c ^ key
		output.append(res)
	h_res = "".join(["{:02x}".format(x) for x in output])
	return binascii.unhexlify(h_res).decode('utf-8')
	
if len(sys.argv) != 2:
	print("ERR: provide a filename.")
	exit()
	
keystroke_file = sys.argv[1]

with open(keystroke_file, "rb") as encrypted_log:
	ciphertext = bytearray(encrypted_log.read())
	
with open("decrypted_" + keystroke_file.split("\\")[-1], "w", encoding="utf-8") as outfile:
	total_len = int(struct.unpack("<I", ciphertext[4:8])[0])
	offset = 0x10
	while offset < total_len:
		keystroke_ciphertext = ciphertext[offset:]
		curr_len = int(struct.unpack("<H", keystroke_ciphertext[2:4])[0]) + 4
		keystroke_ciphertext = keystroke_ciphertext[:curr_len]
		outfile.write(decrypt_strings(keystroke_ciphertext))
		offset += curr_len
