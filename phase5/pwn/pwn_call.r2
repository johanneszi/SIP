# nop call sym.collision
s 0x004028d6
wao nop

# overwrite sym.check_sgx_status
s 0x004028f0
wa mov eax, 0
s 0x004028f5
wao nop

# overwrite return value of collide_gold
s 0x0040294f
wao nop
wa mov eax, 1
