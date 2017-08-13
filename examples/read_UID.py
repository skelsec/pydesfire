from pyDESFire.readers import *
from pyDESFire.pydesfire import *

if __name__ == '__main__':
	logging.basicConfig(level=logging.INFO)
	logger = logging.getLogger(__name__)

	reader = PCSCReader()
	reader.connect()
	card = Desfire(reader)
	cardversion = card.GetCardVersion()

	print 'UID: %s' % (cardversion.UID.encode('hex').upper())
	