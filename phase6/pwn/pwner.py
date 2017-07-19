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

def nopInst(addr):
    r2.cmd('wao nop @ ' + str(addr))

if __name__ == "__main__":

    r2.cmd('oo+') # Open binary for writing
    r2.cmd('aaa') # Analyse

    # Search all invalid SC instructions...
    result = r2.cmdj('/xj '+ '48b8050fff310000000049ba')
    if not result:
        print('No SC protection found!')
    else:
        print('Disabling SC protection!')

        # ..and delete them
        for res in result:
            address = res['offset']
            nops(address, 23)
    
    # Deletes CFI's hash check so the file
    # containing the valid call graph can be
    # arbitrary changed
    nops(0x00401594, 2)
    
    # Increase score in calc_score_gold
    # input parameters in r15d, r14d
    # radare2 cannot assemble instructions with d registers
    # Function is protected with RC but at least 3 test cases
    # has 0,0,0 as input and 0 as result. We multiply one of 
    # the input parameters (stored in ebx) which is also used as an
    # accumolator for the result, with itself, so 0 is returned
    address = 0x00755d56
    seek(address)
    r2.cmd('wxs 0x4401fb') # add ebx, r15d 
    r2.cmd('wxs 0x4401f3') # add ebx, r14d
    r2.cmd('wxs 0x0fafdb') # imul ebx, ebx ; for fun and profit
    address += 9
    nops(address, 9) # nop the remaining bytes

    # Disable collision in main
    nopInst(0x007420a8) # delete instruction call (can be omitted)
    r2.cmd('wa xor eax, eax @ 0x007420a8') # change return
    
    # Insert only $ in setup_level
    nopInst(0x00716b1b) # deletes jmp to * inserter
    
    if len(argv) > 2:
        # Change all results for RC for usec_delay
        nopInst(0x0070e70b)
        r2.cmd('wx 0x40b701 @ 0x0070e70b')

        nopInst(0x00723bae)
        r2.cmd('wx 0x40b701 @ 0x00723bae')

        nopInst(0x0075053f)
        r2.cmd('wx 0x40b701 @ 0x0075053f')

        nopInst(0x00754b7d)
        r2.cmd('wx 0x40b701 @ 0x00754b7d')

        nopInst(0x00769413)
        r2.cmd('wx 0x40b701 @ 0x00769413')

        # Nop all ebx involving instructions in usec_delay
        nopInst(0x007531e3)
        nopInst(0x007531e6)
        nopInst(0x007531ed)
    
        if argv[2] == '0':
            r2.cmd('wa mov ebx, 0xaae60 @ 0x007531e6') # make it slow
        else:
            r2.cmd('wa mov ebx, 0x100 @ 0x007531e6') # make it fast
    
    print('Done')
    
    r2.quit()
