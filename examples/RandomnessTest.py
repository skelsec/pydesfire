import logging
from pyDESFire.readers import *
from pyDESFire.pydesfire import *
from pyDESFire.utils import *


def getRandom(card, key, keyNo, logger):
	logger.debug('Authenticating')
	cmd = None
	keyType = key.GetKeyType()
	if keyType == DESFireKeyType.DF_KEY_AES:
		cmd = DESFireCommand.DFEV1_INS_AUTHENTICATE_AES.value
		params = int2hex(keyNo)
	elif keyType == DESFireKeyType.DF_KEY_2K3DES or keyType == DESFireKeyType.DF_KEY_3K3DES:
		cmd = DESFireCommand.DFEV1_INS_AUTHENTICATE_ISO.value
		params = int2hex(keyNo)
	else:
		raise Exception('Invalid key type!')


	raw_data = card.communicate(cmd,params, autorecieve = False)
	RndB_enc = raw_data
	logger.debug( 'Random B (enc): ' + hex2hexstr(RndB_enc))
	key.CiperInit()
	RndB = key.Decrypt(RndB_enc)
	logger.debug( 'Random B (dec): ' + hex2hexstr(RndB))
	return RndB

def restartSession():
	#### the part below is to abort the authentication and re-start the session
	try:
		card.SelectApplication(0x000000)
	except DESFireCommsException as e:
		if e.status_code == DESFireStatus.ST_CommandAborted.value:
			pass

if __name__ == '__main__':
	global logger

	logging.basicConfig(level=logging.INFO)
	logger = logging.getLogger(__name__)

	bytesCollected = 0

	###
	### !!!ATTENTION!!!
	### The key must be valid, otherwise you will be only getting garbage
	###    as the random challenge is sent encrypted to the creader!
	###
	KEY = DESFireKey(hexstr2hex('00 00 00 00 00 00 00 00'), DESFireKeyType.DF_KEY_2K3DES)
	keyNo = 0

	logger.info('[+] Setting up reader and card')
	reader = PCSCReader()
	reader.connect()
	card = Desfire(reader)
	card.SelectApplication(0x000000)

	blocksize = len(getRandom(card, KEY, keyNo ,logger))
	restartSession()

	logger.info('[+] Starting getting random challenges from card')
	try:
		with open('DESFire_RND_bytes.bin', 'wb') as f:
			while True:
				f.write(getRandom(card, KEY, keyNo ,logger))
				bytesCollected += blocksize
				if bytesCollected % 1024 == 0:
					logger.info('[+] Collected %d bytes'%(bytesCollected,))
				restartSession()
	except:
		logger.info('[+] Stopped! Collected %d challenges' % (bytesCollected/blocksize))
			