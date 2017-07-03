# nop call sym.collision
s 0x0040272f
wao nop

# overwrite sym.check_sgx_status
s 0x00402749
wa mov eax, 0
s 0x0040274e
wao nop

# overwrite return value of collide_gold
s 0x004027a8
wao nop
wa mov eax, 1
