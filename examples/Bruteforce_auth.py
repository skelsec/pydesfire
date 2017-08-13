import logging
from pyDESFire.readers import *
from pyDESFire.pydesfire import *
from pyDESFire.utils import *

WELL_KNOWN_KEYS = {
	DESFireKeyType.DF_KEY_2K3DES : [
		'00 00 00 00 00 00 00 00', #DES
		'FF FF FF FF FF FF FF FF', #DES
		'00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00', #2DES
		'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF'  #2DES

	],
	DESFireKeyType.DF_KEY_3K3DES : [
		'00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
		'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF'
	],
	DESFireKeyType.DF_KEY_AES : [
		'00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
		'00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F',
		'00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15',
		'00 10 20 30 40 50 60 70 80 90 A0 B0 B0 A0 90 80',
		'10 18 20 28 30 38 40 48 50 58 60 68 70 78 80 88',
		'00 FF 00 FF 00 FF 00 FF 00 FF 00 FF 00 FF 00 FF',
		'00 11 00 22 00 33 00 44 00 55 00 66 00 77 00 88',
		'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF'
	]
}

def testAuth(key, keyNo, card):
	try:
		card.Authenticate(keyNo, key)
		return True
	except DESFireAuthException as e:
		return False

def restartSession():
	#### the part below is to abort the authentication and re-start the session
	try:
		card.SelectApplication(0x000000)
	except DESFireCommsException as e:
		if e.status_code == DESFireStatus.ST_CommandAborted.value:
			pass

if __name__ == '__main__':

	reader = PCSCReader()
	reader.connect()
	card = Desfire(reader)
	card.SelectApplication(0x000000)

	print card.GetKeySettings()

	foundkeys = []
	
	for keytype in WELL_KNOWN_KEYS:
		for keydata in WELL_KNOWN_KEYS[keytype]:
			key = DESFireKey(hexstr2hex(keydata), keytype)
			for keyNo in range(16):
				
				while True:
					try:
						print 'Testing key keyNo: %d keytype: %s keydata %s' % (keyNo, keytype.name, keydata)
						if testAuth(key, keyNo, card):
							print '[+] Found key! keyNo: %d keytype: %s keydata %s' % (keyNo, keytype.name, keydata)
							foundkeys.append((keyNo, keytype.name, keydata))
							restartSession()
							break

						break
					except DESFireCommsException as e:
						if e.status_code == DESFireStatus.ST_CommandAborted:
							print 'session reset needed!'
							#restartSession()
						elif e.status_code == DESFireStatus.ST_KeyDoesNotExist:
							break
						else:
							raise e

	if len(foundkeys) != 0:
		print 'Finished! Found %d keys!' % (len(foundkeys),)
		for k in foundkeys:
			print k
	else:
		print 'Finished! No keys found :('
	