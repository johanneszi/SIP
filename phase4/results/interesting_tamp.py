from sys import argv
from random import randint
from struct import pack, unpack
import r2pipe

if len(argv) != 2:
    print('Please provide program name!')
    exit(1)

r2 = r2pipe.open(argv[1])

def seek(addr):
    r2.cmd('s '+ str(addr))

class Instruction:
    def __init__(self, address=None):
        if address:
            seek(address)
        instruction = r2.cmdj('pdj 1')[0]
        self.type = instruction['type'] if instruction.get('type') else None
        self.size = instruction['size'] if instruction.get('size') else None
        self.jump = instruction['jump'] if instruction.get('jump') else None

def patchMovOfMul(start, mulAddr):
    address = start

    while True:
        seek(address)
        instruction = Instruction()

        if instruction.type == 'call':
            if instruction.jump == mulAddr:
                seek(address - 4)
                r2.cmd('wx 0x00')
                break
        address += instruction.size

if __name__ == "__main__":
    r2.cmd('oo+') # Open binary for writing
    r2.cmd('aaa') # Analyse

    mainAddr = int(r2.cmd('?v sym.main'), 16)
    mulAddr = int(r2.cmd('?v sym.mul'), 16)

    if (mainAddr == 0x0 or mulAddr == 0x0):
        print('mul or main cannot be found!')
        exit(1)

    patchMovOfMul(mainAddr, mulAddr)

    r2.quit()
