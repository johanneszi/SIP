from sys import argv
from random import randint
from struct import pack, unpack
import r2pipe

if len(argv) != 3:
    print('Please provide program name and output file!')
    exit(1)

r2 = r2pipe.open(argv[1])

def randNum():
    return randint(1, 127)

def seek(addr):
    r2.cmd('s '+ str(addr))

class Instruction:
    def __init__(self, address=None):
        if address:
            seek(address)
        instruction = r2.cmdj('pdj 1')[0]
        self.type = instruction['type'] if instruction.get('type') else None
        self.size = instruction['size'] if instruction.get('size') else None


def patch(start, hash):
    address = start

    r2.cmd('wx ' + str(randNum()) + ' @ ' + str(address - 2))

    while True:
        seek(address)
        instruction = Instruction()

        if instruction.type == 'call':
            # Patch the print call that prints the hash value
            # Instead of adding NOPs add Addtitions or ORs that do nothing
            rando = randNum()
            cmd = ''
            if rando > 50:
                cmd = '\"wa add edx, ' + str(hex(rando)) + ';and edx, edi\"'
            else:
                cmd = '\"wa sub edx, ' + str(hex(rando)) + ';or edx, edi\"'
            r2.cmd(cmd)
        elif instruction.type == 'cmp':
            # Patch the result comparison
            if instruction.size == 6:
                seek(address + 2)
            elif instruction.size == 7:
                seek(address + 3)
            else:
                raise Exception("Instructions got corrupted!")

            hash = unpack("<i", pack(">i", hash))[0]
            hash = (hash + (1 << 32)) % (1 << 32) # Built two's compliment
            r2.cmd('wx 0x{:08x}'.format(hash))
        elif instruction.type == 'cjmp':
            # Since the correct hash could not be added by the module pass but the program needs to be executed the condition check was added inverse
            # Therefore the comparision has to be changed
            r2.cmd('wao swap-cjmp')
            break

        address += instruction.size

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

if __name__ == "__main__":
    hashes = []
    # The hash values that have to be patched have to be given comma seperated in an input file
    with open(argv[2], 'r') as f:
        hashes = parse(f.readlines())

    print(hashes)

    r2.cmd('oo+') # Open binary for writing
    r2.cmd('aaa') # Analyse
    # Search all IDs and patch the variables
    for (id, hash) in hashes.items():
        address = int(r2.cmdj('/aj mov esi, ' + str(hex(id)))[0]['offset'])
        patch(address, hash)

    r2.quit()
