from sys import argv
import r2pipe

if len(argv) < 2:
    print('Please provide program name and output file!')
    exit(1)

r2 = r2pipe.open(argv[1])

def seek(addr):
    r2.cmd('s '+ str(addr))

def nops(start, n):
    for i in range(n):
        r2.cmd('wx 0x90 @ ' + str(start + i))

def nop_inst(addr):
    r2.cmd('wao nop @ ' + str(addr))

if __name__ == "__main__":

    r2.cmd('oo+') # Open binary for writing
    r2.cmd('aaa') # Analyse

    # Search all invalid SC instructions...
    result = r2.cmdj('/xj '+ '48b8050fff310000000049ba')
    if not result:
        print('No SC protection found or already patched!')
    else:
        print('Disabling SC protection!')

        # ..and delete them
        for res in result:
            address = res['offset']
            nops(address, 23)

    # Deletes CFI's hash check so the file
    # containing the valid call graph can be
    # arbitrary changed
    print("Deleting CFI graph hash check!")
    nops(0x00401594, 2)

    # Increase score in calc_score_gold
    # input parameters in r15d, r14d, ebx
    # radare2 cannot assemble instructions with d registers
    # Function is protected with RC but at least 3 test cases
    # has 0,0,0 as input and 0 as result. We multiply one of
    # the input parameters (stored in ebx) which is also used as an
    # accumolator for the result, with itself, so 0 is returned
    print("Changing score calculation!")
    address = 0x00755d56
    seek(address)
    r2.cmd('wxs 0x4401fb') # add ebx, r15d
    r2.cmd('wxs 0x4401f3') # add ebx, r14d
    r2.cmd('wxs 0x0fafdb') # imul ebx, ebx ; for fun and profit
    address += 9
    nops(address, 9) # nop the remaining bytes

    # Disable collision in main
    print('Disabling collision checking!')
    nop_inst(0x007420a8) # delete instruction call
    r2.cmd('wa xor eax, eax @ 0x007420a8') # change return to always false

    # Uncomment to invoke eat_gold whenever snake moves
    # print('Enabling \"look mama no hands\" mode!')
    # r2.cmd('wa mov eax, 1 @ 0x007423c6')

    # Uncomment to set high_score to max integer
    # print("Setting high_score to max integer!")
    # save_hc_address = 0x0075b24e
    # nop_inst(save_hc_address) # Make some place
    # seek(save_hc_address)
    # r2.cmd('wxs 0x5b58') # pop rbx, pop rax
    # r2.cmd('wxs b8FFFFFF7F') # mov eax, 0x7FFFFFFF
    # r2.cmd('wxs 0x5053') # push rbx, push rax in the end

    # Insert only $ in setup_level
    nop_inst(0x00716b1b) # deletes jmp to * inserter

    if len(argv) > 2:
        default_speed = 0xaae60
        new_speed = default_speed
        try:
            new_speed = int(argv[2])
            if new_speed < 0:
                new_speed = default_speed
                raise ValueError
        except ValueError:
            print("New speed has to be positive! Defaults to 0x{:08x}!".format(new_speed))

        print("Setting new speed to 0x{:08x}!".format(new_speed))

        # Change all results for RC for usec_delay
        nop_inst(0x0070e70b)
        r2.cmd('wx 0x40b701 @ 0x0070e70b')

        nop_inst(0x00723bae)
        r2.cmd('wx 0x40b701 @ 0x00723bae')

        nop_inst(0x0075053f)
        r2.cmd('wx 0x40b701 @ 0x0075053f')

        nop_inst(0x00754b7d)
        r2.cmd('wx 0x40b701 @ 0x00754b7d')

        nop_inst(0x00769413)
        r2.cmd('wx 0x40b701 @ 0x00769413')

        # Nop all ebx involving instructions in usec_delay
        nop_inst(0x007531e3)
        nop_inst(0x007531e6)
        nop_inst(0x007531ed)

        # Nice values to try:
        #   0xaae60 - slow and comfortable
        #   0x100 - fast can't be seen
        r2.cmd('wa mov ebx, 0x{:08x} @ 0x007531e6'.format(new_speed))

    print('Done')

    r2.quit()
