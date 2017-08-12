import zlib

def calcPadSize(data, CipherBlocksize):
	padsize = 0
	l = len(data)
	if l < CipherBlocksize:
		return CipherBlocksize - l
	m = l % CipherBlocksize
	if m != 0:
		if l < CipherBlocksize:
			padsize = m
		else:
			padsize = (((l/CipherBlocksize)+1)*CipherBlocksize) - l
	return padsize

def zb(b):
	b = b & 0b11111110
	return b

def CRC32(data):
	return int2hex(zlib.crc32(data) & 0xffffffff)

def bytelist2hex(data, separator = ' '):
	return separator.join('{:02x}'.format(x) for x in data).upper()

def intlist2hex(iL):
	return ''.join([int2hex(a) for a in iL])

def hexstr2bytelist(data):
	data = data.strip()
	data = data.replace(' ','')
	if len(data)%2 != 0:
		data = '0'+data
	data =  data.decode('hex')
	return [ord(a) for a in data]

def hexstr2hex(data):
	out = ''
	data = data.strip()
	for b in data.split(' '):
		if len(b) != 2:
			b = '0' + b
		out += b.decode('hex')
	return out

def hex2hexstr(data, separator = ' '):
	return separator.join(a.encode('hex').upper() for a in data)


def hex2bytelist(data):
	return hexstr2bytelist(data.encode('hex'))

def chunks(data, n):
	i = 0
	while i < len(data):
		yield data[i:i+n]
		i += n

def int2hex(i):
	t = (hex(i)[2:]).replace('L','')
	if len(t)%2 != 0:
		t = '0'+t
	return t.decode('hex')

def hex2int(h):
	return int(h.encode('hex'),16)

def int2intlist(i):
	return
	
def RotateBlockLeft(block):
	"""
	works with hex
	"""
	return block[1:] + block[0]

def RotateBlockRight(block):
	"""
	works with hex
	"""
	return block[-1] + block[:-1]

def BitShiftLeft(data):
	data = bin(hex2int(data))[2:]
	print data
	print data[1:] + '0'
	return int2hex(int(data[1:] + '0',2))
	

def XOR(A,B):
	cs = len(A)
	if len(B) > cs:
		cs = len(B)
	#calculates the XOR of two arbitrary long hexstrs
	res =  int2hex( (int(A.encode('hex'),16) ^ int(B.encode('hex'),16)))
	if len(res) < cs:
		return '\x00'*(cs-len(res)) + res
	return res