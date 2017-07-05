import r2pipe
import sys

r2 = r2pipe.open('./InterestingProgram-rewritten', ['w', 'A'])

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

def isReport(type, opcode):
	# We search for a mov whoose second parameter
	# is an address.
	if type == 'mov':
		sAddr = opcode.split(',')[1].strip()
		try:
			int(sAddr, 16)
		except:
			return False

		# Look up what string is pointing to
		# that address
		hashString = r2.cmd('ps @ ' + sAddr)
		if 'corrupted' in hashString:
			return True

	return False

def findReport(start):
	address = start

	while True:
		seek(address)
		instruction = r2.cmdj('pdj 1')
		(type, opcode, size) = currentInst(instruction)

		# If no more instructions - break
		if not type or type == 'invalid' or not size:
			break

		if isReport(type, opcode):
			yield address

		address += size

def patchReport(address):
	# Write an unconditional JMP to
	# jump over report function
	seek(address-6)
	r2.cmd('wx 0x90')
	seek(address-5)
	r2.cmd('wx 0xe9')

if __name__ == "__main__":
	dyninstInst = int(r2.cmd('?v sym.InterestingProcedure_dyninst'), 16)
	dyninstMain = int(r2.cmd('?v sym.main_dyninst'), 16)
	startAddress = 0x0

	if dyninstMain != 0x0:
		startAddress = dyninstMain
	elif dyninstInst != 0x0:
		startAddress = dyninstInst
	else:
		print("Open something rewritten with dyninst!")
		exit(1)

	r2.cmd('oo+')

	for reportAddr in findReport(startAddress):
		patchReport(reportAddr)

	r2.quit()
