from sys import argv
from random import randint
from struct import pack, unpack
import r2pipe

if len(argv) != 2:
    print('Please provide program name and output file!')
    exit(1)

r2 = r2pipe.open(argv[1])

def seek(addr):
    r2.cmd('s '+ str(addr))

class Instruction:
    def __init__(self, address=None):
        if address:
            seek(address)
        instruction = r2.cmdj('pdj 1')

        instruction = instruction[0]
        self.type = instruction['type'] if instruction.get('type') else None
        self.size = instruction['size'] if instruction.get('size') else None
        self.jump = instruction['jump'] if instruction.get('jump') else None

def parse(input):
    # parse the file that may contain further output to only return IDs and hashes
    result = {}

    for line in input:
        line = line.split(',')
        if len(line) == 2:
            try:
                id = int(line[0])
                hash = int(line[1])
                result[id] = hash
            except ValueError:
                continue

    return result

def findPrintf():
    for symbol in r2.cmdj('isj'):
        if 'imp.printf' in symbol['name']:
            return symbol['vaddr']
    raise Exception("Printf not found!")

if __name__ == "__main__":

    r2.cmd('oo+') # Open binary for writing
    r2.cmd('aaa') # Analyse

    # Search all IDs and patch the variables
    result = r2.cmdj('/xj '+ '48b8050fff310000000049ba')
    if not result:
        print("Nothing found!")
        r2.quit()
        exit()

    for res in result:
        address = res['offset']
        for i in range(23):
            seek(address+i)
            r2.cmd('wx 0x90')
    
    # Deletes hash for CFI
    seek('0x00401594')
    r2.cmd('wx 0x9090')
    
    # Increase score in calc_score_gold
    address = 0x00755d56
    seek(address)
    r2.cmd('wx 0x4401fb')
    seek(address+3)
    r2.cmd('wx 0x4401f3')
    seek(address+6)
    r2.cmd('wx 0x0fafdb')
    address += 9
    for i in range(9):
        seek(address+i)
        r2.cmd('wx 0x90')
        
    
    # Disable collision in main
    seek('0x007420a8')
    r2.cmd('wao nop')
    seek('0x007420a8')
    r2.cmd('wa xor eax, eax')
    
    # Insert only $ in setup_level
    seek('0x00716b1b')
    r2.cmd('wao nop')
    
    r2.quit()
