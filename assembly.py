#!/usr/bin/python3
# bin assembly decoder


from capstone import *
import sys, argparse

def main():

	parser = argparse.ArgumentParser(description='load args')
	parser.add_argument('-o',"--output", required = True, help ="provide decoded filename")
	parser.add_argument('-s' ,"--source" , required= True, help = "provide ml source filename")
	args = parser.parse_args()
	source = args.source
	output = args.output
	try:
		with open(source,"rb") as f:
			arquivo = f.read()
	except:
		print("type a valid source filename")
		sys.exit()
	
	f.close()
	with open (output,"w") as f:
		md = Cs(CS_ARCH_X86, CS_MODE_32)
		for i in md.disasm(arquivo, 0x1000):
			f.write("0x%x:\t%s\t%s \n" %(i.address, i.mnemonic, i.op_str))



if __name__ == '__main__': 
	sys.exit(main())
