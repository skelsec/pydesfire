def bytelist2hex(data):
	return ''.join('{:02x}'.format(x) for x in data)
	