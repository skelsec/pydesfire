from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.util import toHexString


class Reader():
	def __init__(self):
		self.reader_name = ''
		self.reader_type = ''


class PCSCReader(Reader):
	def __init__(self, request_timeout = 1, cardtype = None):
		Reader.__init__(self)
		self.reader_type = 'PCSC'
		self.request_timeout = request_timeout
		if cardtype == None:
			self.cardtype = AnyCardType()
		self.cardrequest = None
		self.reader_name = None


	def connect(self):
		self.cardrequest = CardRequest( timeout=self.request_timeout, cardType=self.cardtype )
		self.cardservice = self.cardrequest.waitforcard()
		self.cardservice.connection.connect()
		self.reader_name = self.cardservice.connection.getReader()

	def sendAPDU(self, apdu):
		#data, sw1, sw2 =
		return self.cardservice.connection.transmit(apdu)

	def getATR(self):
		return self.cardservice.connection.getATR()
	