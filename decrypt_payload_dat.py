import sys

def decrypt_dat(ciphertext, filename):
	acc = ciphertext[0] + (ciphertext[1] << 0x8) + (ciphertext[2] << 0x10) + (ciphertext[3] << 0x18)
	acc &= 0xFFFFFFFF
	with open("decrypted_" + filename, "wb") as decrypted_dat:
		for c in ciphertext[4:]:
			tmp = (acc + acc) & 0xFFFFFFFF
			acc = acc + (tmp * 8) + 0x107E666D
			acc &= 0xFFFFFFFF
			key = (((acc >> 0x18) & 0xFF) + ((acc >> 0x10) & 0xFF) + ((acc >> 0x8) & 0xFF) + (acc & 0xFF)) & 0xFF
			decrypted_dat.write((c ^ key).to_bytes(1,"little"))

if len(sys.argv) != 2:
	print("ERR: provide a filename.")
	exit()
	
filename = sys.argv[1]
with open(filename, "rb") as encrypted_dat:
	ciphertext = bytearray(encrypted_dat.read())
	
decrypt_dat(ciphertext, filename.split("\\")[-1])
