def bytelist2hex(data, separator = ''):
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
	
def RotateBlockLeft(block):
	return block[1:] + [block[0]]

def RotateBlockRight(block):
	return [block[-1]] + block[:-1]

def BitShiftLeft(data, blocksize):
	data = hex2bytelist(data)
	temp = []
	for i in range(blocksize-1): 
		t = (data[i] << 1) | (data[i+1] >> 7)
		temp.append(t)
	temp.append( (data[-1]*2)&0xFF)
	return intlist2hex(temp)