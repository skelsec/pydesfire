from utils import *
from enum import Enum

class SmartCardTypes(Enum):
	DESFIRE		= 0
	DESFIRE_EV1	= 1
	DESFIRE_EV2 = 2
	MIFARE_CLASSIC = 3
	MIFARE_CLASSIC_EV1 = 4
	ICLASS = 5


class SmartCard():
	def __init__(self, type, ATR):
		self.type = type
		self.ATR = ATR

	def toDict(self):
		temp = {}
		temp['type'] = self.type.name
		temp['ATR'] = bytelist2hex(self.ATR).upper()
		return temp
