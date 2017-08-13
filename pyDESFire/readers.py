import abc
from enum import Enum
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.util import toHexString
from Queue import Queue

class ReaderType(Enum):
	DUMMY = 0
	PCSC = 1

class Reader():
	def __init__(self):
		self.reader_name = ''
		self.reader_type = ''

	@abc.abstractmethod
	def connect(self):
		raise NotImplementedError

	@abc.abstractmethod
	def sendAPDU(self, apdu):
		raise NotImplementedError

	@abc.abstractmethod
	def getATR(self):
		raise NotImplementedError

class DummyReader(Reader):
	def __init__(self, request_timeout = 1, cardtype = None):
		Reader.__init__(self)
		self.reader_type = ReaderType.DUMMY
		self.request_timeout = request_timeout
		self.cardrequest = None
		self.reader_name = 'DUMMY'

		self.responses = Queue()
		self.requests = None


	def connect(self):
		return 'OK'

	def sendAPDU(self, apdu):
		if self.requests != None:
			if not self.requests.empty():
				assert apdu == self.requests.get(timeout = 1)
		return self.responses.get()

	def getATR(self):
		return ('')

	def addResponse(self,data):
		# data should be in format (responseBytes, SW1, SW2)
		self.responses.put(data)

	def addExpectedRequest(self, data):
		if self.requests == None:
			self.requests = Queue()
		self.requests.put(data)

class PCSCReader(Reader):
	def __init__(self, request_timeout = 1, cardtype = None):
		Reader.__init__(self)
		self.reader_type = ReaderType.PCSC
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
	