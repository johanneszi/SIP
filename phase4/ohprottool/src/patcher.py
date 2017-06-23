import sys
from sys import argv
from random import *
import r2pipe

if len(argv) != 3:
    print('Please provide program name and output file!')
    exit(1)

r2 = r2pipe.open(argv[1])


def seek(addr):
    r2.cmd('s '+ str(addr))

def currentInst(instruction):
    if not instruction or len(instruction) == 0: 
	    return (None, None, None)

    # Take the first instruction
    currentInstruction = instruction[0] 

    type = None
    opcode = None
    size = None

    # Populate instruction parameters
    if currentInstruction.get('type'):
        type = currentInstruction['type']
    if currentInstruction.get('opcode'):
	    opcode = currentInstruction['opcode']
    if currentInstruction.get('size'):
        size = int(currentInstruction['size'])
	
    return (type, opcode, size) 
    
def patchCmp(start, hash):
    address = start

    while True:
        seek(address)
        instruction = r2.cmdj('pdj 1')
        (type, opcode, size) = currentInst(instruction)

        # If no more instructions - break
        if type == 'cmp':
            if size == 6:
                seek(address + 2)
            elif size == 7:
                seek(address + 3)
            else:
                print("No idea")
            
            hash = str(hex(hash)).replace('0x', '').zfill(8)
            r2.cmd('wx 0x' + hash[6:] + hash[4:6] + hash[2:4] + hash[0:2]) 
            break
        
        address += size
	
def patchJmp(start):
    address = start

    while True:
        seek(address)
        instruction = r2.cmdj('pdj 1')
        (type, opcode, size) = currentInst(instruction)

        # If no more instructions - break
        if type == 'cjmp':
            r2.cmd('wx 0x74')
            break 
        
        address += size
        
def patchCall(start):
    address = start

    while True:
        seek(address)
        instruction = r2.cmdj('pdj 1')
        (type, opcode, size) = currentInst(instruction)

        # If no more instructions - break
        if type == 'call':
            rando = randint(1, 127)
            print(rando)
            r2.cmd('wa add edx, ' + str(hex(rando)))
            seek(address + 3)
            r2.cmd('wa and edx, edx')
            break
            
        address += size

def parse(input):
    result = []
    
    for line in input:
        line = line.split(',')
        if len(line) == 2:
            try:
                id = int(line[0])
                hash = int(line[1])
                result += [(id, hash)]
            except ValueError:
                continue
    
    return result
            
if __name__ == "__main__":
    hashes = []
    
    with open(argv[2], 'r') as f:
        hashes = parse(f.readlines())
    
    print(hashes)
    
    r2.cmd('oo+') # Open binary for writing
    r2.cmd('aaa') # Analyse
    
    for (id, hash) in hashes:
        address = int(r2.cmdj('/aj mov esi, ' + str(hex(id)))[0]['offset'])
        patchCall(address)
        patchCmp(address, hash)
        patchJmp(address)
        
    r2.quit()
    
