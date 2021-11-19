import sys
import struct 

def decrypt_reg(ciphertext, init_key):
	acc = init_key ^ 0xA7847046
	acc &= 0xFFFFFFFF
	with open("decrypted_registry", "wb") as decrypted_dat:
		for c in ciphertext:
			tmp = (acc + acc) & 0xFFFFFFFF
			acc = acc + (tmp * 8) + 0x107E666D
			acc &= 0xFFFFFFFF
			key = (((acc >> 0x18) & 0xFF) + ((acc >> 0x10) & 0xFF) + ((acc >> 0x8) & 0xFF) + (acc & 0xFF)) & 0xFF
			decrypted_dat.write((c ^ key).to_bytes(1,"little"))


if len(sys.argv) != 3:
	print("ERR: provide the registry data file")
	print("ERR: provide the malicious DLL filename")
	exit()
	
reg_file = sys.argv[1]
dll_file = sys.argv[2]

with open(reg_file, "rb") as encrypted_dat:
	ciphertext = bytearray(encrypted_dat.read())
	
with open(dll_file, "rb") as dll:
	dll_partialheader = bytearray(dll.read()[:0x150])
	
timedatestamp_offset = dll_partialheader[0x3c] + 0x8
init_key = struct.unpack("<I",dll_partialheader[timedatestamp_offset:timedatestamp_offset+0x4])[0]

decrypt_reg(ciphertext, init_key)
