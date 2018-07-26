# Wallet Backup File format:
#{
#    "0000000000000000000000000000000000000000000000000000000000000000": "0000000000000000000000000000000000000000000000000000000000000003",  # version
#    "0000000000000000000000000000000000000000000000000000000000000001": "17066335A804D52FC54FB2E036F236636222E03BE07511D7E2B15A55B25A50FF",  # Salt (random uint256)
#    "0000000000000000000000000000000000000000000000000000000000000002": "BD34136720EA25E5B5B5A2AF68ABADD94AFE4EE3DD592400F4BD8EE7FC6F0024",  # Wallet Key
#    "0000000000000000000000000000000000000000000000000000000000000003": "1D15EE9E57BAFE6425B968F5368BECF85D87D7204693AB86284D74853AC0A38F",  # Check (password fan validity check?)
#    "0000000000000000000000000000000000000000000000000000000000000004": "A30E0A32ED41C8607AA9212843392E853FCBCB4E7CB194E35C94F07F91DE59EF",  # Representative
#    "0000000000000000000000000000000000000000000000000000000000000005": "8208BD79655E7141DCFE792084AB6A8FDFFFB56F37CE30ADC4C2CC940E276A8B",  # Encrypted seed = 9F1D53E732E48F25F94711D5B22086778278624F715D9B2BEC8FB81134E7C904
																																			  # (random uint256)
#    "0000000000000000000000000000000000000000000000000000000000000006": "0000000000000000000000000000000000000000000000000000000000000002",  # Number of deterministic accounts
#    "8933B4083FE0E42A97FF0B7E16B9B2CEF93D31318700B328D6CF6CE931BBF8D4": "0000000000000000000000000000000000000000000000000000000100000000",  # Account 0: xrb_34bmpi65zr967cdzy4uy4twu7mqs9nrm53r1penffmuex6ruqy8nxp7ms1h1
#    "DAE58DB4087564DD1E3B32C2E301A9F288F2F006A31951816AB36E92F2A61548": "0000000000000000000000000000000000000000000000000000000100000001"   # Account 1: xrb_3pq7jpt1ixd6unh5pep4we1tmwnaydr1farsc81poeugkdsce7cain19myin
#}

import sys
from hashlib import blake2b
from bitstring import BitArray
from pure25519 import ed25519_oop as ed25519
from timeit import Timer
import random

def xrb_account(address):
	# Given a string containing an XRB address, confirm validity and provide resulting hex address
	if len(address) == 64 and (address[:4] == 'xrb_'):
		account_map = "13456789abcdefghijkmnopqrstuwxyz"				# each index = binary value, account_lookup[0] == '1'
		account_lookup = {}
		for i in range(0,32):											# populate lookup index with prebuilt bitarrays ready to append
			account_lookup[account_map[i]] = BitArray(uint=i,length=5)

		acrop_key = address[4:-8]										# we want everything after 'xrb_' but before the 8-char checksum
		acrop_check = address[-8:]										# extract checksum
			
		# convert base-32 (5-bit) values to byte string by appending each 5-bit value to the bitstring, essentially bitshifting << 5 and then adding the 5-bit value.
		number_l = BitArray()									
		for x in range(0, len(acrop_key)):	
			number_l.append(account_lookup[acrop_key[x]])		
		number_l = number_l[4:]											# reduce from 260 to 256 bit (upper 4 bits are never used as account is a uint256)
			
		check_l = BitArray()
		for x in range(0, len(acrop_check)):
			check_l.append(account_lookup[acrop_check[x]])
		check_l.byteswap()												# reverse byte order to match hashing format

		result = number_l.hex.upper()

		# verify checksum
		h = blake2b(digest_size=5)
		h.update(number_l.bytes)
		if (h.hexdigest() == check_l.hex):return result
		return False
	return False
	
def account_xrb(account):
	# Given a string containing a hex address, encode to public address format with checksum
	account_map = "13456789abcdefghijkmnopqrstuwxyz"					# each index = binary value, account_lookup['00001'] == '3'
	account_lookup = {}
	for i in range(0,32):												# populate lookup index for binary string to base-32 string character
		account_lookup[BitArray(uint=i,length=5).bin] = account_map[i]
	
	account = BitArray(hex=account)										# hex string > binary
		
	# get checksum
	h = blake2b(digest_size=5)								
	h.update(account.bytes)									
	checksum = BitArray(hex=h.hexdigest())					
		
	# encode checksum
	checksum.byteswap()													# swap bytes for compatibility with original implementation
	encode_check = ''
	for x in range(0,int(len(checksum.bin)/5)):			
			encode_check += account_lookup[checksum.bin[x*5:x*5+5]]		# each 5-bit sequence = a base-32 character from account_map
	
	# encode account
	encode_account = ''
	while len(account.bin) < 260:										# pad our binary value so it is 260 bits long before conversion (first value can only be 00000 '1' or 00001 '3')
		account = '0b0' + account
	for x in range(0,int(len(account.bin)/5)):
			encode_account += account_lookup[account.bin[x*5:x*5+5]]	# each 5-bit sequence = a base-32 character from account_map
		
	return 'xrb_'+encode_account+encode_check							# build final address string

def private_public(private):
	return ed25519.SigningKey(private).get_verifying_key().to_bytes()
	
def seed_account(seed, index):
	# Given an account seed and index #, provide the account private and public keys
	h = blake2b(digest_size=32)
	
	seed_data = BitArray(hex=seed)
	seed_index = BitArray(int=index,length=32)
	
	h.update(seed_data.bytes)
	h.update(seed_index.bytes)
	
	account_key = BitArray(h.digest())
	return account_key.bytes, private_public(account_key.bytes)

def pow_threshold(check):
	if check > b'\xFF\xFF\xFF\xC0\x00\x00\x00\x00': return True
	return False
	
def pow_validate(pow, hash):
	pow_data = bytearray.fromhex(pow)
	hash_data = bytearray.fromhex(hash)
	
	h = blake2b(digest_size=8)
	pow_data.reverse()
	h.update(pow_data)
	h.update(hash_data)
	final = bytearray(h.digest())
	final.reverse()
	
	return pow_threshold(final)
	
def pow_generate(hash):
	hash_bytes = bytearray.fromhex(hash)
	#print(hash_bytes.hex())
	#time.sleep(5)
	test = False
	inc = 0
	while not test:
			inc += 1
			random_bytes = bytearray((random.getrandbits(8) for i in range(8)))		# generate random array of bytes
			for r in range(0,256):
				random_bytes[7] =(random_bytes[7] + r) % 256						# iterate over the last byte of the random bytes
				h = blake2b(digest_size=8)
				h.update(random_bytes)
				h.update(hash_bytes)
				final = bytearray(h.digest())
				final.reverse()
				test = pow_threshold(final)
				if test: break
		
	random_bytes.reverse()
	return random_bytes.hex()	

def test():
	seed = "9F1D53E732E48F25F94711D5B22086778278624F715D9B2BEC8FB81134E7C904"	
	priv_key, pub_key = seed_account(seed,1)
	acc = account_xrb(pub_key.hex())

	#{
	#    "type": "state",
	#    "account": "xrb_34bmpi65zr967cdzy4uy4twu7mqs9nrm53r1penffmuex6ruqy8nxp7ms1h1",
	#    "previous": "C8E5B875778702445B25657276ABC56AA9910B283537CA438B2CC59B0CF93712",
	#    "representative": "xrb_34bmpi65zr967cdzy4uy4twu7mqs9nrm53r1penffmuex6ruqy8nxp7ms1h1",
	#    "balance": "000000FC6F7C40458122964CFFFFFF9C",
	#    "link": "C8E5B875778702445B25657276ABC56AA9910B283537CA438B2CC59B0CF93712",
	#    "work": "266063092558d903",
	#    "signature": "17D6EAF3438CC592333594C96D023D742F7F38669F2DA6A763877F6958B3A76572169652E55D05E0759E114252765DB9E0F3BF55FA89F28E300CAF829C89250E"
	#}

	action="receive"
	block = "C8E5B875778702445B25657276ABC56AA9910B283537CA438B2CC59B0CF93712"
	rep = "xrb_34bmpi65zr967cdzy4uy4twu7mqs9nrm53r1penffmuex6ruqy8nxp7ms1h1"
	bal = 1 # balance after send/receive
	times = []

	if action=="send":
		link = xrb_account("xrb_34bmpi65zr967cdzy4uy4twu7mqs9nrm53r1penffmuex6ruqy8nxp7ms1h1") # destination address
		print("sending nano")
	elif action=="receive" or action=="open":
		link = "C8E5B875778702445B25657276ABC56AA9910B283537CA438B2CC59B0CF93712" # send block hash
		print("receiving nano")
	elif action=="change":
		link = "0000000000000000000000000000000000000000000000000000000000000000"
		print("changing representative")

	print("Profiling PoW...")
	for x in range(1,11):
		print("Round "+str(x)+": Generating PoW...")
		start = Timer()
		pow = pow_generate(block)
		end = Timer()
		elapsed = int(end-start)
		times.append(elapsed)
		print("Elapsed time: "+str(elapsed)+" seconds")
		print("Valid: "+str(pow_validate(pow,block))+" Value: "+pow)

	print("Average elapsed time: "+str(sum(times)/len(times))+" seconds")

	bh = blake2b(digest_size=32)

	bh.update(BitArray(hex="0000000000000000000000000000000000000000000000000000000000000006").bytes) # preamble

	bh.update(BitArray(hex=xrb_account(acc)).bytes) # account
	print("Account         ",acc)

	bh.update(BitArray(hex=block).bytes)	# previous block
	print("Previous        ",block)

	bh.update(BitArray(hex=xrb_account(rep)).bytes) # representative
	print("Representative  ",rep)

	bh.update(BitArray(hex=format(bal,'032x')).bytes) # final balance
	print("Balance         ",bal)

	bh.update(BitArray(hex=link).bytes) # link
	if action=="send":
		print("Send to         ",account_xrb(link))
	elif action=="receive" or action=="open":
		print("Receive         ",link)

	print("Hash            ",bh.hexdigest())																				

	sig = ed25519.SigningKey(priv_key+pub_key).sign(bh.digest())														# work is not included in signature
	print("Signature       ",sig.hex())

if __name__ == '__main__':
	test()
