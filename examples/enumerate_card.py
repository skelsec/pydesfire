import logging
from pyDESFire.readers import *
from pyDESFire.pydesfire import *
from pyDESFire.utils import *


#masterkey = DESFireKey(hexstr2hex('00 00 00 00 00 00 00 00'), DESFireKeyType.DF_KEY_2K3DES)
masterkey = None

if __name__ == '__main__':
	import sys
	import json
	import pprint 

	logging.basicConfig(level=logging.DEBUG)
	logger = logging.getLogger(__name__)

	reader = PCSCReader()
	reader.connect()
	card = Desfire(reader)
	card.GetCardVersion()

	if masterkey != None:
		card.Authenticate(0, masterkey)
	card.enumerate()
	
	pp = pprint.PrettyPrinter(indent=4)
	pp.pprint(card.toDict())
	print json.dumps(card.toDict(), indent = 4, sort_keys = True)