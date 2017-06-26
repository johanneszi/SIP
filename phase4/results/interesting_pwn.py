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
        self.opcode = instruction['opcode'] if instruction.get('opcode') else None
        self.ptr = instruction['ptr'] if instruction.get('ptr') else None

def patch(start):
    address = start

    while True:
        seek(address)
        instruction = Instruction()

        if instruction.type == 'invalid':
            return

        if instruction.opcode == 'add rsp, 0x10':
            previousInst = Instruction(address-10)
            hashAddr = previousInst.ptr

            if hashAddr and 'corrupted' in r2.cmd('ps @ ' + str(hashAddr)):
                r2.cmd('wao nop @ ' + str(address))

        address += instruction.size

if __name__ == "__main__":
    r2.cmd('oo+') # Open binary for writing
    r2.cmd('aaa') # Analyse

    startAddr = int(r2.cmd('?v sym.addChar'), 16)

    if (startAddr == 0x0):
        print('addChar cannot be found!')
        exit(1)

    patch(startAddr)

    r2.quit()
