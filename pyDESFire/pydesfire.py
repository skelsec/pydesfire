#Credits: 
#
###miohtama who worte the original desfire module for python. 
#	URL: https://github.com/miohtama/desfire/
#
###Elmue who created a completely working DESFireEV1 library. (this module is based 99% of his work!)
#	URL: https://www.codeproject.com/Articles/1096861/DIY-electronic-RFID-Door-Lock-with-Battery-Backup
#

from enum import Enum
import logging
import struct
from .readers import PCSCReader, DummyReader
from .cards import SmartCardTypes, SmartCard
from .utils import *

from Crypto.Cipher import DES, DES3, AES
from Crypto import Random


_logger = logging.getLogger(__name__)


class DESFireCommand(Enum):
	# ------- Desfire legacy instructions --------
	
	DF_INS_AUTHENTICATE_LEGACY        = '\x0A'
	DF_INS_CHANGE_KEY_SETTINGS        = '\x54'
	DF_INS_GET_KEY_SETTINGS           = '\x45'
	DF_INS_CHANGE_KEY                 = '\xC4'
	DF_INS_GET_KEY_VERSION            = '\x64'
	DF_INS_CREATE_APPLICATION         = '\xCA'
	DF_INS_DELETE_APPLICATION         = '\xDA'
	DF_INS_GET_APPLICATION_IDS        = '\x6A'
	DF_INS_SELECT_APPLICATION         = '\x5A'
	DF_INS_FORMAT_PICC                = '\xFC'
	DF_INS_GET_VERSION                = '\x60'
	DF_INS_GET_FILE_IDS               = '\x6F'
	DF_INS_GET_FILE_SETTINGS          = '\xF5'
	DF_INS_CHANGE_FILE_SETTINGS       = '\x5F'
	DF_INS_CREATE_STD_DATA_FILE       = '\xCD'
	DF_INS_CREATE_BACKUP_DATA_FILE    = '\xCB'
	DF_INS_CREATE_VALUE_FILE          = '\xCC'
	DF_INS_CREATE_LINEAR_RECORD_FILE  = '\xC1'
	DF_INS_CREATE_CYCLIC_RECORD_FILE  = '\xC0'
	DF_INS_DELETE_FILE                = '\xDF'
	DF_INS_READ_DATA                  = '\xBD'
	DF_INS_WRITE_DATA                 = '\x3D'
	DF_INS_GET_VALUE                  = '\x6C'
	DF_INS_CREDIT                     = '\x0C'
	DF_INS_DEBIT                      = '\xDC'
	DF_INS_LIMITED_CREDIT             = '\x1C'
	DF_INS_WRITE_RECORD               = '\x3B'
	DF_INS_READ_RECORDS               = '\xBB'
	DF_INS_CLEAR_RECORD_FILE          = '\xEB'
	DF_COMMIT_TRANSACTION             = '\xC7'
	DF_INS_ABORT_TRANSACTION          = '\xA7'
	DF_INS_ADDITIONAL_FRAME           = '\xAF' # data did not fit into a frame, another frame will follow
	# '-------- Desfire EV1 instructions ----------
	
	DFEV1_INS_AUTHENTICATE_ISO        ='\x1A'
	DFEV1_INS_AUTHENTICATE_AES        ='\xAA'
	DFEV1_INS_FREE_MEM                ='\x6E'
	DFEV1_INS_GET_DF_NAMES            ='\x6D'
	DFEV1_INS_GET_CARD_UID            ='\x51'
	DFEV1_INS_GET_ISO_FILE_IDS        ='\x61'
	DFEV1_INS_SET_CONFIGURATION       ='\x5C'
	
	# ---------- ISO7816 instructions ------------
	
	ISO7816_INS_EXTERNAL_AUTHENTICATE ='\x82'
	ISO7816_INS_INTERNAL_AUTHENTICATE ='\x88'
	ISO7816_INS_APPEND_RECORD         ='\xE2'
	ISO7816_INS_GET_CHALLENGE         ='\x84'
	ISO7816_INS_READ_RECORDS          ='\xB2'
	ISO7816_INS_SELECT_FILE           ='\xA4'
	ISO7816_INS_READ_BINARY           ='\xB0'
	ISO7816_INS_UPDATE_BINARY         ='\xD6'


# Status codes (errors) returned from Desfire card
class DESFireStatus(Enum):
	ST_Success               = '\x00'
	ST_NoChanges             = '\x0C'
	ST_OutOfMemory           = '\x0E'
	ST_IllegalCommand        = '\x1C'
	ST_IntegrityError        = '\x1E'
	ST_KeyDoesNotExist       = '\x40'
	ST_WrongCommandLen       = '\x7E'
	ST_PermissionDenied      = '\x9D'
	ST_IncorrectParam        = '\x9E'
	ST_AppNotFound           = '\xA0'
	ST_AppIntegrityError     = '\xA1'
	ST_AuthentError          = '\xAE'
	ST_MoreFrames            = '\xAF' #data did not fit into a frame, another frame will follow
	ST_LimitExceeded         = '\xBE'
	ST_CardIntegrityError    = '\xC1'
	ST_CommandAborted        = '\xCA'
	ST_CardDisabled          = '\xCD'
	ST_InvalidApp            = '\xCE'
	ST_DuplicateAidFiles     = '\xDE'
	ST_EepromError           = '\xEE'
	ST_FileNotFound          = '\xF0'
	ST_FileIntegrityError    = '\xF1'


# Card information about software and hardware version.
class DESFireCardVersion():

	def __init__(self):
		self.hardwareVendorId   = None   # The hardware vendor
		self.hardwareType       = None   # The hardware type
		self.hardwareSubType    = None   # The hardware subtype
		self.hardwareMajVersion = None # The hardware major version
		self.hardwareMinVersion = None # The hardware minor version
		self.hardwareStorageSize= None # The hardware storage size
		self.hardwareProtocol   = None    # The hardware protocol

		self.softwareVendorId   = None  # The software vendor
		self.softwareType       = None     # The software type
		self.softwareSubType    = None   # The software subtype
		self.softwareMajVersion = None  # The software major version
		self.softwareMinVersion = None # The software minor version
		self.softwareStorageSize= None # The software storage size
		self.softwareProtocol   = None  # The software protocol

		self.UID      = None    # The serial card number
		self.batchNo  = None    # The batch number
		self.cwProd   = None    # The production week (BCD)
		self.yearProd = None    # The production year (BCD)
		self.rawBytes = None

	def parse(self, data):
		self.rawBytes = data
		self.hardwareVendorId    = data[0]
		self.hardwareType        = data[1]
		self.hardwareSubType     = data[2]
		self.hardwareMajVersion  = data[3]
		self.hardwareMinVersion  = data[4]
		self.hardwareStorageSize = data[5]
		self.hardwareProtocol    = data[6]

		self.softwareVendorId    = data[7]
		self.softwareType        = data[8]
		self.softwareSubType     = data[9]
		self.softwareMajVersion  = data[10]
		self.softwareMinVersion  = data[11]
		self.softwareStorageSize = data[12]
		self.softwareProtocol    = data[13]

		self.UID      = data[14:21]        # The serial card number
		self.batchNo  = data[21:25]        # The batch number
		self.cwProd   = data[26]           # The production week (BCD)
		self.yearProd = data[27]           # The production year (BCD)

	def __repr__(self):
		temp =  "--- Desfire Card Details ---\r\n"
		temp += "Hardware Version: %d.%d\r\n"% (hex2int(self.hardwareMajVersion), hex2int(self.hardwareMinVersion))
		temp += "Software Version: %d.%d\r\n"% (hex2int(self.softwareMajVersion), hex2int(self.softwareMinVersion))
		temp += "EEPROM size:      %d bytes\r\n"% (1 << ((hex2int(self.hardwareStorageSize) / 2)))
		temp += "Production :       week %X, year 20%02X\r\n" % (hex2int(self.cwProd), hex2int(self.yearProd))
		temp += "UID no  : %s\r\n" % (hex2hexstr(self.UID),)
		temp += "Batch no: %s\r\n" % (hex2hexstr(self.batchNo),)
		return temp

	def toDict(self):
		temp = {}
		temp['rawBytes']            = self.rawBytes.encode('hex')
		temp['hardwareVendorId']    = self.hardwareVendorId.encode('hex')
		temp['hardwareType']        = self.hardwareType.encode('hex')
		temp['hardwareSubType']     = self.hardwareSubType.encode('hex')
		temp['hardwareMajVersion']  = self.hardwareMajVersion.encode('hex')
		temp['hardwareMinVersion']  = self.hardwareMinVersion.encode('hex')
		temp['hardwareStorageSize'] = self.hardwareStorageSize.encode('hex')
		temp['hardwareProtocol']    = self.hardwareProtocol.encode('hex')
		temp['softwareVendorId']    = self.softwareVendorId.encode('hex')
		temp['softwareType']        = self.softwareType.encode('hex')
		temp['softwareSubType']     = self.softwareSubType.encode('hex')
		temp['softwareMajVersion']  = self.softwareMajVersion.encode('hex')
		temp['softwareMinVersion']  = self.softwareMinVersion.encode('hex')
		temp['softwareStorageSize'] = self.softwareStorageSize.encode('hex')
		temp['softwareProtocol']    = self.softwareProtocol.encode('hex')
		temp['UID']      = self.UID.encode('hex')
		temp['batchNo']  = self.batchNo.encode('hex')
		temp['cwProd']   = self.cwProd.encode('hex')
		temp['yearProd'] = self.yearProd.encode('hex')
		return temp
 


# MK = Application Master Key or PICC Master Key
class DESFireKeySettings(Enum):

	# ------------ BITS 0-3 ---------------
	KS_ALLOW_CHANGE_MK                = 0x01 # If this bit is set, the MK can be changed, otherwise it is frozen.
	KS_LISTING_WITHOUT_MK             = 0x02 # Picc key: If this bit is set, GetApplicationIDs, GetKeySettings do not require MK authentication.
											  # App  key: If this bit is set, GetFileIDs, GetFileSettings, GetKeySettings do not require MK authentication.
	KS_CREATE_DELETE_WITHOUT_MK       = 0x04 # Picc key: If this bit is set, CreateApplication does not require MK authentication.
											  # App  key: If this bit is set, CreateFile, DeleteFile do not require MK authentication.
	KS_CONFIGURATION_CHANGEABLE       = 0x08 # If this bit is set, the configuration settings of the MK can be changed, otherwise they are frozen.
	
	# ------------ BITS 4-7 (not used for the PICC master key) -------------
	KS_CHANGE_KEY_WITH_MK             = 0x00 # A key change requires MK authentication
	KS_CHANGE_KEY_WITH_KEY_1          = 0x10 # A key change requires authentication with key 1
	KS_CHANGE_KEY_WITH_KEY_2          = 0x20 # A key change requires authentication with key 2
	KS_CHANGE_KEY_WITH_KEY_3          = 0x30 # A key change requires authentication with key 3
	KS_CHANGE_KEY_WITH_KEY_4          = 0x40 # A key change requires authentication with key 4 
	KS_CHANGE_KEY_WITH_KEY_5          = 0x50 # A key change requires authentication with key 5
	KS_CHANGE_KEY_WITH_KEY_6          = 0x60 # A key change requires authentication with key 6
	KS_CHANGE_KEY_WITH_KEY_7          = 0x70 # A key change requires authentication with key 7
	KS_CHANGE_KEY_WITH_KEY_8          = 0x80 # A key change requires authentication with key 8
	KS_CHANGE_KEY_WITH_KEY_9          = 0x90 # A key change requires authentication with key 9
	KS_CHANGE_KEY_WITH_KEY_A          = 0xA0 # A key change requires authentication with key 10
	KS_CHANGE_KEY_WITH_KEY_B          = 0xB0 # A key change requires authentication with key 11
	KS_CHANGE_KEY_WITH_KEY_C          = 0xC0 # A key change requires authentication with key 12
	KS_CHANGE_KEY_WITH_KEY_D          = 0xD0 # A key change requires authentication with key 13
	KS_CHANGE_KEY_WITH_TARGETED_KEY   = 0xE0 # A key change requires authentication with the same key that is to be changed
	KS_CHANGE_KEY_FROZEN              = 0xF0 # All keys are frozen
	
	# -------------------------------------
	KS_FACTORY_DEFAULT                = 0x0F

def calc_key_settings(mask):
	if type(mask) is list:
		#not parsing, but calculating
		res = 0
		for keysetting in mask:
			res += keysetting.value
		return res & 0xFF


	a=2147483648L
	result = []
	while a>>1:
		a = a>>1
		masked = mask&a
		if masked:
			if DESFireKeySettings(masked):
				result.append(DESFireKeySettings(masked))
	return result


class DESFireAccessRights(Enum):

	AR_KEY0  = 0x00 # Authentication with application key 0 required (master key)
	AR_KEY1  = 0x01 # Authentication with application key 1 required
	AR_KEY2  = 0x02 # ...
	AR_KEY3  = 0x03
	AR_KEY4  = 0x04
	AR_KEY5  = 0x05
	AR_KEY6  = 0x06
	AR_KEY7  = 0x07
	AR_KEY8  = 0x08
	AR_KEY9  = 0x09
	AR_KEY10 = 0x0A
	AR_KEY11 = 0x0B
	AR_KEY12 = 0x0C
	AR_KEY13 = 0x0D
	AR_FREE  = 0x0E # Always allowed even without authentication
	AR_NEVER = 0x0F # Always forbidden even with authentication

class DESFireFilePermissions():

	def __init__(self):
		self.ReadAccess         = None
		self.WriteAccess        = None
		self.ReadAndWriteAccess = None
		self.ChangeAccess       = None

	def pack(self):
		return (self.ReadAccess << 12) | (self.WriteAccess <<  8) | (self.ReadAndWriteAccess <<  4) | self.ChangeAccess;
	
	def unpack(self, data):
		self.ReadAccess         = bool((data >> 12) & 0x0F)
		self.WriteAccess        = bool((data >>  8) & 0x0F)
		self.ReadAndWriteAccess = bool((data >>  4) & 0x0F)
		self.ChangeAccess       = bool((data      ) & 0x0F)

	def __repr__(self):
		temp =  '----- DESFireFilePermissions ---\r\n'
		if self.ReadAccess:
			temp += 'READ|'
		if self.WriteAccess:
			temp += 'WRITE|'
		if self.ReadAndWriteAccess:
			temp += 'READWRITE|'
		if self.ReadAndWriteAccess:
			temp += 'CHANGE|'
		return temp

	def toDict(self):
		temp = {}
		temp['ReadAccess']         = self.ReadAccess
		temp['WriteAccess']        = self.WriteAccess
		temp['ReadAndWriteAccess'] = self.ReadAndWriteAccess
		temp['ChangeAccess']       = self.ChangeAccess
		return temp
	


# Defines if data transmitted to files is encrypted (with the session key) or secured with a MAC
class DESFireFileEncryption(Enum):

	CM_PLAIN   = 0x00
	CM_MAC     = 0x01   # not implemented (Plain data transfer with additional MAC)
	CM_ENCRYPT = 0x03   # not implemented (Does not make data stored on the card more secure. Only encrypts the transfer between Teensy and the card)


class DESFireFileType(Enum):

	MDFT_STANDARD_DATA_FILE             = 0x00
	MDFT_BACKUP_DATA_FILE               = 0x01 # not implemented
	MDFT_VALUE_FILE_WITH_BACKUP         = 0x02 # not implemented
	MDFT_LINEAR_RECORD_FILE_WITH_BACKUP = 0x03 # not implemented
	MDFT_CYCLIC_RECORD_FILE_WITH_BACKUP = 0x04 # not implemented


class DESFireFileSettings:

	def __init__(self):

		self.FileType    = None #DESFireFileType
		self.Encryption  = None #DESFireFileEncryption
		self.Permissions = DESFireFilePermissions()
		# ----------------------------
		# used only for MDFT_STANDARD_DATA_FILE and MDFT_BACKUP_DATA_FILE
		self.FileSize    = None #uint32_t
		# -----------------------------
		# used only for MDFT_VALUE_FILE_WITH_BACKUP
		self.LowerLimit  = None #uint32_t
		self.UpperLimit  = None #uint32_t
		self.LimitedCreditValue   = None
		self.LimitedCreditEnabled = None #bool
		# -----------------------------
		# used only for MDFT_LINEAR_RECORD_FILE_WITH_BACKUP and MDFT_CYCLIC_RECORD_FILE_WITH_BACKUP
		self.RecordSize           = None #uint32_t
		self.MaxNumberRecords     = None #uint32_t
		self.CurrentNumberRecords = None 	#uint32_t

	def parse(self, data):
		self.FileType	= DESFireFileType(hex2int(data[0]))
		self.Encryption	= DESFireFileEncryption(hex2int(data[1]))
		self.Permissions.unpack(struct.unpack('>H',data[2:4])[0])
		
		if self.FileType == DESFireFileType.MDFT_LINEAR_RECORD_FILE_WITH_BACKUP:
			self.RecordSize = struct.unpack('<I', data[4:6] + '\x00\x00')[0]  
			self.MaxNumberRecords = struct.unpack('<I', data[6:8] + '\x00\x00')[0]
			self.CurrentNumberRecords = struct.unpack('<I', data[8:10] + '\x00\x00')[0]

		elif self.FileType == DESFireFileType.MDFT_STANDARD_DATA_FILE:
			self.FileSize = struct.unpack('<I', data[4:6] + '\x00\x00')[0]


		else:
			# TODO: We can still access common attributes
			# raise NotImplementedError("Please fill in logic for file type {:02X}".format(resp[0]))
			pass

	def __repr__(self):
		temp = ' ----- DESFireFileSettings ----\r\n'
		temp += 'File type: %s\r\n' % (self.FileType.name)
		temp += 'Encryption: %s\r\n' % (self.Encryption.name)
		temp += 'Permissions: %s\r\n' % (repr(self.Permissions))
		if self.FileType == DESFireFileType.MDFT_LINEAR_RECORD_FILE_WITH_BACKUP:
			temp += 'RecordSize: %d\r\n' % (self.RecordSize)
			temp += 'MaxNumberRecords: %d\r\n' % (self.MaxNumberRecords)
			temp += 'CurrentNumberRecords: %d\r\n' % (self.CurrentNumberRecords)

		elif self.FileType == DESFireFileType.MDFT_STANDARD_DATA_FILE:
			temp += 'File size: %d\r\n' % (self.FileSize)

		return temp

	def toDict(self):
		temp = {}
		temp['FileType'] = self.FileType.name
		temp['Encryption'] = self.Encryption.name
		temp['Permissions'] = self.Permissions.toDict()
		temp['LowerLimit'] = self.LowerLimit
		temp['UpperLimit'] = self.UpperLimit
		temp['LimitedCreditValue'] = self.LimitedCreditValue
		temp['LimitedCreditEnabled'] = self.LimitedCreditEnabled
		if self.FileType == DESFireFileType.MDFT_LINEAR_RECORD_FILE_WITH_BACKUP:
			temp['RecordSize'] = self.RecordSize
			temp['MaxNumberRecords'] = self.MaxNumberRecords
			temp['CurrentNumberRecords'] = self.CurrentNumberRecords
		elif self.FileType == DESFireFileType.MDFT_STANDARD_DATA_FILE:
			temp['FileSize'] = self.FileSize
		return temp



class DESFireCmac(Enum):

	MAC_None   = 0
	# Transmit data:
	MAC_Tmac   = 1 # The CMAC must be calculated for the TX data sent to the card although this Tx CMAC is not transmitted
	MAC_Tcrypt = 2 # To the parameters sent to the card a CRC32 must be appended and then they must be encrypted with the session key    
	# Receive data:
	MAC_Rmac   = 4 # The CMAC must be calculated for the RX data received from the card. If status == ST_Success -> verify the CMAC in the response
	MAC_Rcrypt = 8 # The data received from the card must be decrypted with the session key
	# Combined:
	MAC_TmacRmac   = MAC_Tmac   | MAC_Rmac
	MAC_TmacRcrypt = MAC_Tmac   | MAC_Rcrypt
	MAC_TcryptRmac = MAC_Tcrypt | MAC_Rmac


# These values must be OR-ed with the key number when executing command DF_INS_CHANGE_KEY
class DESFireKeyType(Enum):

	DF_KEY_2K3DES  = 0x00 # for DFEV1_INS_AUTHENTICATE_ISO + DF_INS_AUTHENTICATE_LEGACY
	DF_KEY_3K3DES  = 0x40 # for DFEV1_INS_AUTHENTICATE_ISO
	DF_KEY_AES     = 0x80 # for DFEV1_INS_AUTHENTICATE_AES
	DF_KEY_INVALID = 0xFF    

class DESFireCipher(Enum):

	KEY_ENCIPHER = 0
	KEY_DECIPHER = 1

# Cipher Block Chaining mode
class DESFireCBC(Enum):
	CBC_SEND = 0
	CBC_RECEIVE = 1

################ Exceptions
class DESFireException(Exception):
	def __init__(self, msg):
		super(Exception,self).__init__()
		self.msg = msg

class DESFireAuthException(DESFireException):
	def __init__(self, msg):
		super(DESFireException,self).__init__(msg)

class DESFireCommsException(DESFireException):
	def __init__(self, status_code):
		super(DESFireException,self).__init__(DESFireStatus(status_code).name)
		self.status_code = DESFireStatus(status_code)
		self.msg = DESFireStatus(status_code).name
################

class Desfire(SmartCard):

	def __init__(self, reader, logger=None):
		SmartCard.__init__(self,SmartCardTypes.DESFIRE, reader.getATR())
		# boring init stuff
		self.reader = reader
		if logger:
			self.logger = logger
		else:
			self.logger = _logger

		
		self.isAuthenticated = False
		self.lastAuthKeyNo = None
		self.sessionKey = None
		self.lastSelectedApplication = 0x00

		self.versioninfo = None
		self.applications = []

	###### INTERNAL FUNCTIONS

	def wrap_command(self, cmd, parameters = None):
		res = '\x90'
		if parameters:
			return res + cmd + '\x00\x00' + int2hex(len(parameters)) + parameters + '\x00'
		else:
			return res + cmd + '\x00\x00\x00'

	def _communicate(self, rawdata, autorecieve = True):
		"""
		data : the raw data to be sent to the card
		"""
		result = ''
		while True:
			rawdata = hex2bytelist(rawdata)
			self.logger.debug("[+] Sending APDU : %s" % (bytelist2hex(rawdata),))
			response, sw1, status = self.reader.sendAPDU(rawdata)
			self.logger.debug("[+] Card response: %s SW1: %x SW2: %x" % (bytelist2hex(response), sw1, status))

			#converting everything from list of integers to hex
			if len(response) >0:
				response = intlist2hex(response)
			else:
				response = ''
			sw1      = int2hex(sw1)
			status   = int2hex(status)
			
			if sw1 != '\x91':
				if status == DESFireStatus.ST_AuthentError.value:
					raise DESFireAuthException('Card returned status ST_AuthentError')
				raise DESFireCommsException(status)
			if status not in [DESFireStatus.ST_Success.value, DESFireStatus.ST_NoChanges.value, DESFireStatus.ST_MoreFrames.value]:
				if status == DESFireStatus.ST_AuthentError.value:
					raise DESFireAuthException('Card returned status ST_AuthentError')
				raise DESFireCommsException(status)

			result += response

			if status != DESFireStatus.ST_MoreFrames.value or not autorecieve:
				break
			else:
				rawdata = self.wrap_command(DESFireCommand.DF_INS_ADDITIONAL_FRAME.value)

		return result, status



	def communicate(self, cmd, data, isEncryptedComm = False, withTXCMAC = False, autorecieve = True ):
		"""
		cmd : the DESFire instruction byte (in hex format)
		data: optional parameters (in hex format)
		isEncryptedComm: bool indicates if the communication should be sent encrypted
		withTXCMAC: bool indicates if CMAC should be calculated
		autorecieve: bool indicates if the receptions should implement paging in case there is more deata to be sent by the card back then the max message size
		"""
		result = []

		#sanity check
		if withTXCMAC or isEncryptedComm:
			if not self.isAuthenticated:
				raise Exception('Cant perform CMAC calc without authantication!')
		
		#encrypt the communication
		if isEncryptedComm:
			raise Exception('Not implemented')
			if withTXCMAC:
				return
			else:
				return
		#communication with the card is not encrypted, but CMAC might need to be calculated
		else:
			#calculate cmac for outgoing message
			if withTXCMAC:
				cmacdata = cmd + data
				TXCMAC = self.sessionKey.CalculateCmac(cmacdata)
				self.logger.debug("TXCMAC      : " + hex2hexstr(TXCMAC))
				response, status = self._communicate(self.wrap_command(cmd, data), autorecieve)
			#no encryption, no cmac calculation. this is the case when there is no authentication
			else:
				response, status = self._communicate(self.wrap_command(cmd, data), autorecieve)
		
		if self.isAuthenticated and len(response) >= 8 and status == DESFireStatus.ST_Success.value:
			#after authentication, there is always an 8 bytes long CMAC coming from the card, to ensure message integrity
			#todo: verify CMAC
			if len(response) == 8:
				if self.sessionKey.keyType == DESFireKeyType.DF_KEY_2K3DES or self.sessionKey.keyType == DESFireKeyType.DF_KEY_3K3DES:
					RXCMAC = response
					response = ''
				else:
					#there is no CMAC
					return response
			else:
					RXCMAC = response[-8:]
					response = response[:-8]

			cmacdata = response + status
			RXCAMAC_CALC = self.sessionKey.CalculateCmac(cmacdata)
			self.logger.debug("RXCMAC      : " + hex2hexstr(RXCMAC))
			self.logger.debug("RXCAMAC_CALC: " + hex2hexstr(RXCAMAC_CALC))

		return response

	

	def security_check(self):
		#check for UID randomization, by calling getversion 2 times and comparing the UIDs
		ver_n = self.GetCardVersion()
		ver_n_1 = self.GetCardVersion()
		if ver_n.UID == ver_n_1.UID:
			print '[!] Random UID not enabled!'
		#check for Masterkey settings, need evaluation table for that
		MF = DESFireApplication(0x000000)
		MF.enumerate(self)

		if MF.keytype == DESFireKeyType.DF_KEY_INVALID:
			print '[!]Master KEY type unknown. This is strange'
		elif MF.keytype == DESFireKeyType.DF_KEY_2K3DES:
			print '[!]Master KEY encryption type FAIL'
		elif MF.keytype == DESFireKeyType.DF_KEY_3K3DES or MF.keytype == DESFireKeyType.DF_KEY_AES:
			print '[+]Master KEY type OK'

		if MF.keycount != 1:
			print 'Strange'
		
		if DESFireKeySettings.KS_ALLOW_CHANGE_MK in MF.keysettings:
			print 'Warning, key can be changed later (but only by supplying the original key)'
		if DESFireKeySettings.KS_LISTING_WITHOUT_MK in MF.keysettings:
			print 'Warning, enumeration of the card is possible without authentication'
		if DESFireKeySettings.KS_CREATE_DELETE_WITHOUT_MK in MF.keysettings:
			print 'Warning, apps can be created without authentication'
		if DESFireKeySettings.KS_CONFIGURATION_CHANGEABLE in MF.keysettings:
			print 'Warning, key config can be changed (but only by supplying the original key)'

		#check for application key settings, need evaulation table for that
		#check for unprotected apps/files, need evalua... no, actually we dont
		return None

	def enumerate(self):
		self.versioninfo = self.GetCardVersion()
		### this is for the ROOT dir (main app)
		appids = [0x000000]

		appids += self.GetApplicationIDs()
		### actual apps now
		for appid in appids:
			app = DESFireApplication(appid)
			app.enumerate(self)
			self.applications.append(app)

	def toDict(self):
		temp = SmartCard.toDict(self)
		temp ['versioninfo'] = self.versioninfo.toDict()
		temp ['applications'] = []
		for app in self.applications:
			temp ['applications'].append(app.toDict())
		return temp

	################################## CARD COMMUNICATION METHODS

	###### GENERIC FUNCTIONS

	def GetCardVersion(self):
		"""Gets card version info blob
		Version info contains the UID, Batch number, production week, production year, .... of the card
		Authentication is NOT needed to call this function
		BEWARE: DESFire card has a security feature called "Random UID" which means that without authentication it will give you a random UID each time you call this function!

		Args:
			None

		Returns:
			DESFireCardVersion: Object containing all card version info parsed
		"""
		self.logger.debug('Getting card version info')
		cmd = DESFireCommand.DF_INS_GET_VERSION.value
		raw_data = self.communicate(cmd, '', withTXCMAC=self.isAuthenticated) 
		cv = DESFireCardVersion()
		cv.parse(raw_data)
		self.logger.debug(repr(cv)) 
		return cv

	def FormatCard(self):
		"""Formats the card
		WARNING! THIS COMPLETELY WIPES THE CARD AND RESETS IF TO A BLANK CARD!!
		Authentication is needed to call this function

		Args:
			None

		Returns:
			None
		"""
		self.logger.debug('Formatting card')
		cmd = DESFireCommand.DF_INS_FORMAT_PICC.value
		self.communicate(cmd, '', withTXCMAC=self.isAuthenticated)


	###### Application related

	def GetApplicationIDs(self):
		"""Lists all application on the card
		Authentication is NOT needed to call this function

		Args:
			None

		Returns:
			list: A list of application IDs, in a 4 byte hex form
		"""
		self.logger.debug("GetApplicationIDs")
		appids = []
		cmd = DESFireCommand.DF_INS_GET_APPLICATION_IDS.value
		raw_data = self.communicate(cmd, '', withTXCMAC=self.isAuthenticated)

		pointer = 0
		apps = []
		while pointer < len(raw_data):
			appid = (hex2int(raw_data[pointer]) << 16) + (hex2int(raw_data[pointer+1]) << 8) + hex2int(raw_data[pointer+2])
			self.logger.debug("Reading %d %08x", pointer, appid)
			apps.append(appid)
			pointer += 3

		return apps
		

	def SelectApplication(self, appid):
		"""Choose application on a card on which all the following commands will apply.
		Authentication is NOT ALWAYS needed to call this function. Depends on the application settings.

		Args:
			appid (int): The application ID of the app to be selected

		Returns:
			None
		"""
		self.logger.debug('Selecting application with AppID %s' % (appid,))
		parameters =  int2hex((appid >> 16) & 0xff)+int2hex((appid >> 8) & 0xff)+int2hex((appid >> 0) & 0xff)
		

		cmd = DESFireCommand.DF_INS_SELECT_APPLICATION.value
		self.communicate(cmd, parameters)
		#if new application is selected, authentication needs to be carried out again
		self.isAuthenticated = False
		self.lastSelectedApplication = appid

	def CreateApplication(self, appid, keysettings, keycount, type):
		"""Creates application on the card with the specified settings
		Authentication is ALWAYS needed to call this function.

		Args:
			appid (int)       : The application ID of the app to be created
			keysettings (list): Key settings to be applied to the application to be created. MUST contain entryes derived from the DESFireKeySettings enum
			keycount (int)    : 
			type (int)        : Key type that will specify the encryption used for authenticating to this application and communication with it. MUST be coming from the DESFireKeyType enum

		Returns:
			None
		"""
		self.logger.debug('Creating application with appid: 0x%x, ' %(appid))
		appid = int2hex((appid >> 16) & 0xff)+int2hex((appid >> 8) & 0xff)+int2hex((appid >> 0) & 0xff)
		params = appid + int2hex(calc_key_settings(keysettings)) + int2hex(keycount|type.value)
		cmd = DESFireCommand.DF_INS_CREATE_APPLICATION.value
		self.communicate(cmd, params, withTXCMAC=self.isAuthenticated)

	def DeleteApplication(self, appid):
		"""Deletes the application specified by appid
		Authentication is ALWAYS needed to call this function.

		Args:
			appid (int)       : The application ID of the app to be deleted
		Returns:
			None
		"""
		self.logger.debug('Deleting application for AppID 0x%x', (appid))

		appid = int2hex((appid >> 16) & 0xff)+int2hex((appid >> 8) & 0xff)+int2hex((appid >> 0) & 0xff)

		params = appid
		cmd = DESFireCommand.DF_INS_DELETE_APPLICATION.value
		self.communicate(cmd, params, withTXCMAC=self.isAuthenticated)


	###### FILE FUNTCIONS

	def GetFileIDs(self):
		"""Lists all files belonging to the application currently selected. (SelectApplication needs to be called first)
		Authentication is NOT ALWAYS needed to call this function. Depends on the application/card settings.

		Args:
			None

		Returns:
			list: A list of file IDs, in a 4 byte hex form
		"""
		self.logger.debug('Enumerating all files for the selected application')
		fileIDs = []

		cmd = DESFireCommand.DF_INS_GET_FILE_IDS.value
		raw_data = self.communicate(cmd, '', withTXCMAC=self.isAuthenticated)
		if len(raw_data) == 0:
			self.logger.debug("No files found")
		else:
			for byte in raw_data:
				fileIDs.append(hex2int(byte))
			self.logger.debug("File ids: %s" % (''.join([str(id) for id in fileIDs]),))
		return fileIDs

	def GetFileSettings(self, fileid):
		"""Gets file settings for the File identified by fileid.(SelectApplication needs to be called first)
		Authentication is NOT ALWAYS needed to call this function. Depends on the application/card settings.

		Args:
			fileid (int): FileID to get the settings for

		Returns:
			DESFireFileSettings: An object describing all settings for the file
		"""
		self.logger.debug('Getting file settings for file %s' % (fileid,))

		cmd = DESFireCommand.DF_INS_GET_FILE_SETTINGS.value
		raw_data = raw_data = self.communicate(cmd, int2hex(fileid), withTXCMAC=self.isAuthenticated)

		file_settings = DESFireFileSettings()
		file_settings.parse(raw_data)
		return file_settings

	def ReadFileData(self,fileid):
		"""Read file data for fileID (SelectApplication needs to be called first)
		Authentication is NOT ALWAYS needed to call this function. Depends on the application/card settings.

		Args:
			fileid (int): FileID to get the settings for

		Returns:
			str: the file data bytes
		"""
		self.logger.debug('Reading file data for file %s' % (fileid,))

		parameters = int2hex(fileid) + '\x00'*6
		cmd = DESFireCommand.DF_INS_READ_DATA.value

		buffer = self.communicate(cmd, parameters, withTXCMAC=self.isAuthenticated)
		self.logger.debug('File %s Data: ' % (fileid,bytelist2hex(buffer)))

		return buffer


	###### CRYPTO KEYS RELATED FUNCTIONS


	def GetKeySettings(self):
		"""Gets the key settings for the currently selected application. (SelectApplication needs to be called first, otherwise it's getting the settings for the Master Key)
		Authentication is NOT ALWAYS needed to call this function. Depends on the app/card settings

		Args:
			appid (int) : The application ID of the app to be deleted
		Returns:
			tuple: Containing keysettings ( list of DESFireKeySettings enum entries ), keycount, keytype (DESFireKeyType)
		"""
		self.logger.debug('Getting key settings')

		cmd = DESFireCommand.DF_INS_GET_KEY_SETTINGS.value
		raw_data = self.communicate(cmd, '', withTXCMAC=self.isAuthenticated)

		keysettings = calc_key_settings(hex2int(raw_data[0]))
		keycount =  hex2int(raw_data[1]) & 0x0F
		keytype = DESFireKeyType(hex2int(raw_data[1]) & 0xF0)

		self.logger.debug("Settings: %s, KeyCount: %d, KeyType: %s\r\n" % ('|'.join(a.name for a in keysettings), keycount, keytype))

		return keysettings, keycount, keytype

	def	GetKeyVersion(self, keyNo):
		"""Gets the key version for the key identified by keyno. (SelectApplication needs to be called first, otherwise it's getting the settings for the Master Key)
		Authentication is ALWAYS needed to call this function.

		Args:
			keyNo (int) : The key number
		Returns:
			str: key version byte
		"""
		self.logger.debug('Getting key version for keyid %x' %(keyNo,))

		params = int2hex(keyNo)
		cmd = DESFireCommand.DF_INS_GET_KEY_VERSION.value
		raw_data = self.communicate(cmd, params)
		self.logger.debug('Got key version 0x%s for keyid %x' %(raw_data.encode('hex'),keyNo))
		return raw_data

	def ChangeKeySettings(self, newKeySettings):
		"""Changes key settings for the key that was used to authenticate with in the current session.
		Authentication is ALWAYS needed to call this function.

		Args:
			newKeySettings (list) : A list with DESFireKeySettings enum value
		
		Returns:
			None
		"""
		self.logger.debug('Changing key settings to %s' %('|'.join(a.name for a in newKeySettings),))
		params = int2hex(calc_key_settings(newKeySettings))
		cmd = DESFireCommand.DF_INS_CHANGE_KEY_SETTINGS.value
		raw_data = self.communicate(cmd)


	def ChangeKey(self, keyNo, newKey, curKey):
		"""Changes current key (curKey) to a new one (newKey) in specified keyslot (keyno)
		Authentication is ALWAYS needed to call this function.

		Args:
			keyNo  (int) : Key number
			newKey (DESFireKey)    : The new key
			curKey (DESFireKey)    : The current key for that keyslot
		
		Returns:
			None
		"""

		self.logger.debug(' -- Changing key --')
		#self.logger.debug('Changing key No: %s from %s to %s' % (keyNo, newKey, curKey))
		if not self.isAuthenticated:
			raise Exception('Not authenticated!')

		self.logger.debug('Curr IV: ' + hex2hexstr(self.sessionKey.IV))
		self.logger.debug('curKey : ' + hex2hexstr(curKey.keyBytes))
		self.logger.debug('newKey : ' + hex2hexstr(newKey.keyBytes))

		isSameKey = keyNo == self.lastAuthKeyNo
		#self.logger.debug('isSameKey : ' + str(isSameKey))
		
		cryptogram = ''

		# The type of key can only be changed for the PICC master key.
		# Applications must define their key type in CreateApplication().
		if self.lastSelectedApplication == 0x00:
			keyNo = keyNo | newKey.keyType.value
		
		#The following if() applies only to application keys.
    	#For the PICC master key b_SameKey is always true because there is only ONE key (#0) at the PICC level.
		if not isSameKey:
			keyData_xor = XOR(newKey.GetKeyBytes(), curKey.GetKeyBytes())
			cryptogram += keyData_xor
		else:
			cryptogram += newKey.GetKeyBytes()
		 
		if newKey.keyType == DESFireKeyType.DF_KEY_AES:
			cryptogram += int2hex(newKey.keyVersion)

		#self.logger.debug( (int2hex(DESFireCommand.DF_INS_CHANGE_KEY.value) + int2hex(keyNo) + cryptogram).encode('hex'))
		Crc = DESFireCRC32(DESFireCommand.DF_INS_CHANGE_KEY.value + int2hex(keyNo), cryptogram)
		self.logger.debug('Crc        : ' + hex2hexstr(Crc))
		Crc_rev = Crc[::-1]
		cryptogram += Crc_rev

		if not isSameKey:
			CrcNew = DESFireCRC32(newKey.GetKeyBytes())
			self.logger.debug('Crc New Key: ' + hex2hexstr(CrcNew))
			cryptogram += CrcNew[::-1]

		self.logger.debug('Cryptogram      : ' + hex2hexstr(cryptogram))
		cryptogram_enc = self.sessionKey.PaddedEncrypt(cryptogram)
		self.logger.debug('Cryptogram (enc): ' + hex2hexstr(cryptogram_enc))

		params = int2hex(keyNo) + cryptogram_enc
		cmd = DESFireCommand.DF_INS_CHANGE_KEY.value
		raw_data = self.communicate(cmd, params)

		#If we changed the currently active key, then re-auth is needed!
		if isSameKey:
			self.isAuthenticated = False
			self.sessionKey = None

		return

	def Authenticate(self, key_id, key, challenge = None):
		"""Does authentication to the currently selected application with keyid (key_id)
		Authentication is NEVER needed to call this function.

		Args:
			key_id  (int)         : Key number
			key (DESFireKey)      : The key used for authentication
			challenge (DESFireKey): The challenge supplied by the reader to the card on the challenge-response authentication. 
									It will determine half of the session Key bytes (optional)
									It's there for testing and crypto thiunkering purposes
		
		Returns:
			DESFireKey : the session key used for future communications with the card in the same session
		"""
		self.logger.debug('Authenticating')
		self.isAuthenticated = False
		cmd = None
		keyType = key.GetKeyType()
		if keyType == DESFireKeyType.DF_KEY_AES:
			cmd = DESFireCommand.DFEV1_INS_AUTHENTICATE_AES.value
			params = int2hex(key_id)
		elif keyType == DESFireKeyType.DF_KEY_2K3DES or keyType == DESFireKeyType.DF_KEY_3K3DES:
			cmd = DESFireCommand.DFEV1_INS_AUTHENTICATE_ISO.value
			params = int2hex(key_id)
		else:
			raise Exception('Invalid key type!')


		raw_data = self.communicate(cmd,params, autorecieve = False)
		RndB_enc = raw_data
		self.logger.debug( 'Random B (enc): ' + hex2hexstr(RndB_enc))
		if keyType == DESFireKeyType.DF_KEY_3K3DES or keyType == DESFireKeyType.DF_KEY_AES:
			if len(RndB_enc) != 16:
				raise DESFireAuthException('Card expects a different key type. (enc B size is less than the blocksize of the key you specified)')

		key.CiperInit()
		RndB = key.Decrypt(RndB_enc)
		self.logger.debug( 'Random B (dec): ' + hex2hexstr(RndB))
		RndB_rot = RotateBlockLeft(RndB)
		self.logger.debug( 'Random B (dec, rot): ' + hex2hexstr(RndB_rot))

		if challenge != None:
			RndA = challenge
		else:
			RndA = Random.get_random_bytes(len(RndB))
		self.logger.debug( 'Random A: ' + hex2hexstr(RndA))
		RndAB = RndA + RndB_rot
		self.logger.debug( 'Random AB: ' + hex2hexstr(RndAB))
		RndAB_enc = key.Encrypt(RndAB)
		self.logger.debug( 'Random AB (enc): ' + hex2hexstr(RndAB_enc))

		params = RndAB_enc
		cmd = DESFireCommand.DF_INS_ADDITIONAL_FRAME.value
		raw_data = self.communicate(cmd,params, autorecieve = False)
		#raw_data = hexstr2bytelist('91 3C 6D ED 84 22 1C 41')
		RndA_enc = raw_data
		self.logger.debug('Random A (enc): ' + hex2hexstr(RndA_enc))
		RndA_dec = key.Decrypt(RndA_enc)
		self.logger.debug( 'Random A (dec): ' + hex2hexstr(RndA_dec))
		RndA_dec_rot = RotateBlockRight(RndA_dec)
		self.logger.debug( 'Random A (dec, rot): ' + hex2hexstr(RndA_dec_rot))

		if RndA != RndA_dec_rot:
			raise Exception('Authentication FAILED!')

		self.logger.debug( 'Authentication succsess!')
		self.isAuthenticated = True
		self.lastAuthKeyNo = key_id

		self.logger.debug( 'Calculating Session key')
		sessionKeyBytes  = RndA[:4]
		sessionKeyBytes += RndB[:4]

		if key.keySize > 8:
			if keyType == DESFireKeyType.DF_KEY_2K3DES:
				sessionKeyBytes += RndA[4:8]
				sessionKeyBytes += RndB[4:8]
			elif keyType == DESFireKeyType.DF_KEY_3K3DES:
				sessionKeyBytes += RndA[6:10]
				sessionKeyBytes += RndB[6:10]
				sessionKeyBytes += RndA[12:16]
				sessionKeyBytes += RndB[12:16]
			elif keyType == DESFireKeyType.DF_KEY_AES:
				sessionKeyBytes += RndA[12:16]
				sessionKeyBytes += RndB[12:16]

		if keyType == DESFireKeyType.DF_KEY_2K3DES or keyType == DESFireKeyType.DF_KEY_3K3DES:
			sessionKeyBytes = intlist2hex([a & 0b11111110 for a in hex2bytelist(sessionKeyBytes)])
	
		## now we have the session key, so we reinitialize the crypto!!!
		sessionKey = DESFireKey(sessionKeyBytes, keyType)
		sessionKey.CiperInit()
		sessionKey.GenerateCmacSubkeys()

		self.logger.debug( 'Cmac1: ' + sessionKey.Cmac1.encode('hex').upper())
		self.logger.debug( 'Cmac2: ' + sessionKey.Cmac2.encode('hex').upper())
		self.logger.debug( 'sessionKey: ' + sessionKey.keyBytes.encode('hex').upper())
		self.sessionKey = sessionKey
		return sessionKey


class DESFireKey():
	def __init__(self, keyBytes, keyType):
		self.keyType = keyType
		self.keyBytes = keyBytes
		self.keySize = len(self.keyBytes)
		self.keyVersion = None

		self.IV = None
		self.Cipher = None
		self.CipherBlocksize = None

		self.Cmac1 = None
		self.Cmac2 = None

	def GetKeyBytes(self):
		"""
		Special case: if simple DES key is used the card still expects 16 bytes to be sent (otherwise you get wrong command length or integrity errors)
		"""
		if self.keyType == DESFireKeyType.DF_KEY_2K3DES and self.keySize == 8:
			return self.keyBytes + self.keyBytes
		else:
			return self.keyBytes



	def CiperInit(self):
		#todo assert on key length!
		if self.keyType == DESFireKeyType.DF_KEY_AES:
			#AES is used
			assert self.keySize == 16
			self.CipherBlocksize = 16
			self.ClearIV()
			self.Cipher = AES.new(self.keyBytes, AES.MODE_ECB, self.IV)

		elif self.keyType == DESFireKeyType.DF_KEY_2K3DES:
			#DES is used
			if self.keySize == 8:
				self.CipherBlocksize = 8
				self.ClearIV()
				self.Cipher = DES.new(self.keyBytes, DES.MODE_ECB, self.IV)
			#2DES is used (3DES with 2 keys only)
			elif self.keySize == 16:
				self.CipherBlocksize = 8
				self.ClearIV()
				self.Cipher = DES3.new(self.keyBytes, DES.MODE_ECB, self.IV)

			else:
				raise Exception('Key length error!')
			
		elif self.keyType == DESFireKeyType.DF_KEY_3K3DES:
			assert self.keySize == 24
			#3DES is used
			self.CipherBlocksize = 8
			self.ClearIV()
			self.Cipher = DES3.new(self.keyBytes, DES.MODE_ECB, self.IV)

		else:
			raise Exception('Unknown key type!')
		

	def ClearIV(self):
		self.IV = '\x00' * self.CipherBlocksize


	def GetKeyType(self):
		return self.keyType

	def PaddedEncrypt(self, data):
		padsize = 0
		m = len(data) % self.CipherBlocksize
		if m != 0:
			if len(data) < self.CipherBlocksize:
				padsize = m
			else:
				padsize = (((len(data)/self.CipherBlocksize)+1)*self.CipherBlocksize) - len(data)
		return self.Encrypt(data + '\x00'*padsize)

	def Encrypt(self, data):
		#todo assert on blocksize
		result = ''
		for block in chunks(data, self.CipherBlocksize):
			#print 'Block: ' + block.encode('hex')
			block_xor = XOR(block,self.IV)
			#print 'Block (xor): ' + block_xor.encode('hex')
			block_xor_enc = self.Cipher.encrypt(block_xor)
			#print 'Block (dec): ' + block_dec.encode('hex')
			self.IV = block_xor_enc
			result+= block_xor_enc
		return result

	def Decrypt(self, dataEnc):
		#todo assert on blocksize
		result = ''
		for block in chunks(dataEnc, self.CipherBlocksize):
			#print 'Block: ' + block.encode('hex')
			block_dec = self.Cipher.decrypt(block)
			#print 'Block (dec): ' + block_dec.encode('hex')
			block_dec_xor = XOR(block_dec,self.IV)
			#print 'Block (dec, xor): ' + block_dec_xor.encode('hex')
			self.IV = block
			result+= block_dec_xor
		return result


	#Generates the two subkeys mu8_Cmac1 and mu8_Cmac2 that are used for CMAC calulation with the session key
	def GenerateCmacSubkeys(self):
		### THIS PART IS NOT WORKING CORRECTLY!!!
		R = 0x87
		if self.CipherBlocksize == 8:
			R = 0x1B

		data = '\x00'*16
		self.ClearIV()
		data = self.Decrypt(data)
		#print 'Before: ' + data.encode('hex')
		self.Cmac1 = BitShiftLeft(data)[:self.CipherBlocksize]
		if (hex2int(data[0]) & 0x80):
			t = hex2int(self.Cmac1[-1]) ^ R
			self.Cmac1 = self.Cmac1[:-1] + int2hex(t)

		self.Cmac2 = BitShiftLeft(self.Cmac1)
		if (hex2int(self.Cmac1[0]) & 0x80):
			t = hex2int(self.Cmac2[-1]) ^ R
			self.Cmac2 = self.Cmac2[:-1] + int2hex(t)

		#print  'Cmac1: ' + self.Cmac1.encode('hex').upper()
		#print  'Cmac2: ' + self.Cmac2.encode('hex').upper()


	#Calculate the CMAC (Cipher-based Message Authentication Code) from the given data.
	#The CMAC is the initialization vector (IV) after a CBC encryption of the given data.
	def CalculateCmac(self, data):
		# If the data length is not a multiple of the block size -> pad the buffer with 80,00,00,00,....
		### THIS PART IS NOT WORKING CORRECTLY!!!
		cmac = ''
		#print data.encode('hex')
		padsize = calcPadSize(data, self.CipherBlocksize)
		#print padsize
		if padsize != 0:
			data += '\x80' + '\x00'*(padsize-1)
			#print data.encode('hex')
			cmac = XOR(data, self.Cmac2)
		else:
			#print data.encode('hex')
			cmac = XOR(data, self.Cmac1)

		#print cmac.encode('hex')

		cmac_enc = self.Decrypt(cmac)
		self.IV = cmac_enc
		return cmac_enc




class DESFireApplication:
	def __init__(self, appid):
		self.appid = appid
		self.files = []
		self.keysettings = None
		self.keycount = None
		self.keytype = None

	def enumerate(self, card):
		card.SelectApplication(self.appid)
		try:
			#getting the key settings
			self.keysettings, self.keycount, self.keytype = card.GetKeySettings()
		except DESFireAuthException as e:
			pass

		try:
			for fileid in card.GetFileIDs():
				try:
					file = DESFireFile(self.appid, fileid)
					file.enumerate(card)
					self.files.append(file)
				except DESFireAuthException as e:
					self.files.append(DESFireFile(self.appid, fileid))
					pass
				except DESFireCommsException as e:
					if e.status_code == DESFireStatus.ST_PermissionDenied.value:
						self.files.append(DESFireFile(self.appid, fileid))
						pass
		
		except DESFireAuthException as e:
			pass

		except DESFireCommsException as e:
			if e.status_code == DESFireStatus.ST_PermissionDenied.value:
				self.files.append(DESFireFile(self.appid, fileid))
				pass

	def toDict(self):
		temp = {}
		temp['appid'] = hex(self.appid)[2:].rjust(2, '0').upper()
		if self.files:
			temp['files'] = []
			for file in self.files:
				temp['files'] = file.toDict()
		if self.keysettings:
			temp['keysettings'] = []
			for keysetting in self.keysettings:
				temp['keysettings'].append(keysetting.name)
			temp['keycount'] = self.keycount
			temp['keytype'] = self.keytype.name
		return temp

class DESFireFile:
	def __init__(self, appid, fileid):
		self.appid = appid
		self.fileid = fileid
		self.fielsettings = None
		self.filedata = None

	def enumerate(self, card):
		card.SelectApplication(self.appid)
		try:
			for fileid in card.GetFileIDs():
				self.fielsettings = card.GetFileSettings(fileid)		
		except DESFireAuthException as e:
			pass

		try:
			for fileid in card.GetFileIDs():
				self.filedata = card.ReadFileData(fileid)		
		except DESFireAuthException as e:
			pass

	def toDict(self):
		temp = {}
		temp['appid'] = hex(self.appid)[2:].rjust(2, '0').upper()
		temp['fileid'] = hex(self.fileid)[2:].rjust(2, '0').upper()
		if self.fielsettings:
			temp['fielsettings'] = self.fielsettings.toDict()
		if self.filedata:
			temp['filedata'] = self.filedata.encode('hex')
		return temp

