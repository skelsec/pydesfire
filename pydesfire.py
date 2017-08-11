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
from readers import PCSCReader, DummyReader
from cards import SmartCardTypes, SmartCard
from utils import *

from Crypto.Cipher import DES, DES3, AES
from Crypto import Random


_logger = logging.getLogger(__name__)


class DESFireCommand(Enum):


	NOT_AUTHENTICATED   =   255# Just an invalid key number
	MAX_FRAME_SIZE  =   60  #The maximum total length of a packet that is transfered to / from the card

	# ------- Desfire legacy instructions --------
	
	DF_INS_AUTHENTICATE_LEGACY        = 0x0A
	DF_INS_CHANGE_KEY_SETTINGS        =0x54
	DF_INS_GET_KEY_SETTINGS           =0x45
	DF_INS_CHANGE_KEY                 =0xC4
	DF_INS_GET_KEY_VERSION            =0x64
	
	DF_INS_CREATE_APPLICATION         =0xCA
	DF_INS_DELETE_APPLICATION         =0xDA
	DF_INS_GET_APPLICATION_IDS        =0x6A
	DF_INS_SELECT_APPLICATION         =0x5A
	
	DF_INS_FORMAT_PICC                =0xFC
	DF_INS_GET_VERSION                =0x60
	
	DF_INS_GET_FILE_IDS               =0x6F
	DF_INS_GET_FILE_SETTINGS          =0xF5
	DF_INS_CHANGE_FILE_SETTINGS       =0x5F
	DF_INS_CREATE_STD_DATA_FILE       =0xCD
	DF_INS_CREATE_BACKUP_DATA_FILE    =0xCB
	DF_INS_CREATE_VALUE_FILE          =0xCC
	DF_INS_CREATE_LINEAR_RECORD_FILE  =0xC1
	DF_INS_CREATE_CYCLIC_RECORD_FILE  =0xC0
	DF_INS_DELETE_FILE                =0xDF
	
	DF_INS_READ_DATA                  =0xBD
	DF_INS_WRITE_DATA                 =0x3D
	DF_INS_GET_VALUE                  =0x6C
	DF_INS_CREDIT                     =0x0C
	DF_INS_DEBIT                      =0xDC
	DF_INS_LIMITED_CREDIT             =0x1C
	DF_INS_WRITE_RECORD               =0x3B
	DF_INS_READ_RECORDS               =0xBB
	DF_INS_CLEAR_RECORD_FILE          =0xEB
	DF_COMMIT_TRANSACTION             =0xC7
	DF_INS_ABORT_TRANSACTION          =0xA7
	
	DF_INS_ADDITIONAL_FRAME           =0xAF # data did not fit into a frame, another frame will follow
	
	# -------- Desfire EV1 instructions ----------
	
	DFEV1_INS_AUTHENTICATE_ISO        =0x1A
	DFEV1_INS_AUTHENTICATE_AES        =0xAA
	DFEV1_INS_FREE_MEM                =0x6E
	DFEV1_INS_GET_DF_NAMES            =0x6D
	DFEV1_INS_GET_CARD_UID            =0x51
	DFEV1_INS_GET_ISO_FILE_IDS        =0x61
	DFEV1_INS_SET_CONFIGURATION       =0x5C
	
	# ---------- ISO7816 instructions ------------
	
	ISO7816_INS_EXTERNAL_AUTHENTICATE =0x82
	ISO7816_INS_INTERNAL_AUTHENTICATE =0x88
	ISO7816_INS_APPEND_RECORD         =0xE2
	ISO7816_INS_GET_CHALLENGE         =0x84
	ISO7816_INS_READ_RECORDS          =0xB2
	ISO7816_INS_SELECT_FILE           =0xA4
	ISO7816_INS_READ_BINARY           =0xB0
	ISO7816_INS_UPDATE_BINARY         =0xD6


# Status codes (errors) returned from Desfire card
class DESFireStatus(Enum):
	ST_Success               = 0x00
	ST_NoChanges             = 0x0C
	ST_OutOfMemory           = 0x0E
	ST_IllegalCommand        = 0x1C
	ST_IntegrityError        = 0x1E
	ST_KeyDoesNotExist       = 0x40
	ST_WrongCommandLen       = 0x7E
	ST_PermissionDenied      = 0x9D
	ST_IncorrectParam        = 0x9E
	ST_AppNotFound           = 0xA0
	ST_AppIntegrityError     = 0xA1
	ST_AuthentError          = 0xAE
	ST_MoreFrames            = 0xAF #data did not fit into a frame, another frame will follow
	ST_LimitExceeded         = 0xBE
	ST_CardIntegrityError    = 0xC1
	ST_CommandAborted        = 0xCA
	ST_CardDisabled          = 0xCD
	ST_InvalidApp            = 0xCE
	ST_DuplicateAidFiles     = 0xDE
	ST_EepromError           = 0xEE
	ST_FileNotFound          = 0xF0
	ST_FileIntegrityError    = 0xF1


# Card information about software and hardware version.
class DESFireCardVersion():

	def __init__(self):
		self.hardwareVendorId = None   # The hardware vendor
		self.hardwareType     = None   # The hardware type
		self.hardwareSubType  = None   # The hardware subtype
		self.hardwareMajVersion = None # The hardware major version
		self.hardwareMinVersion = None # The hardware minor version
		self.hardwareStorageSize= None # The hardware storage size
		self.hardwareProtocol= None    # The hardware protocol

		self.softwareVendorId  = None  # The software vendor
		self.softwareType   = None     # The software type
		self.softwareSubType  = None   # The software subtype
		self.softwareMajVersion= None  # The software major version
		self.softwareMinVersion = None # The software minor version
		self.softwareStorageSize= None # The software storage size
		self.softwareProtocol  = None  # The software protocol

		self.UID   = None        # The serial card number
		self.batchNo     = None     # The batch number
		self.cwProd     = None         # The production week (BCD)
		self.yearProd    = None        # The production year (BCD)

	def parse(self, data):
		self.hardwareVendorId = data[0]
		self.hardwareType     = data[1]
		self.hardwareSubType  = data[2]
		self.hardwareMajVersion = data[3]
		self.hardwareMinVersion = data[4]
		self.hardwareStorageSize= data[5]
		self.hardwareProtocol= data[6]

		self.softwareVendorId  = data[7]
		self.softwareType   = data[8]
		self.softwareSubType  = data[9]
		self.softwareMajVersion= data[10]
		self.softwareMinVersion = data[11]
		self.softwareStorageSize=data[12]
		self.softwareProtocol  = data[13]

		self.UID   = data[14:21]        # The serial card number
		self.batchNo     = data[21:25]      # The batch number
		self.cwProd     = data[26]           # The production week (BCD)
		self.yearProd    = data[27]          # The production year (BCD)

	def __repr__(self):
		temp =  "--- Desfire Card Details ---\r\n"
		temp += "Hardware Version: %d.%d\r\n"% (self.hardwareMajVersion, self.hardwareMinVersion)
		temp += "Software Version: %d.%d\r\n"% (self.softwareMajVersion, self.softwareMinVersion)
		temp += "EEPROM size:      %d bytes\r\n"% (1 << ((self.hardwareStorageSize / 2)))
		temp += "Production:       week %X, year 20%02X\r\n" % (self.cwProd, self.yearProd)
		temp += "UID no: %s\r\n" % (bytelist2hex(self.UID),)
		temp += "Batch no: %s\r\n" % (bytelist2hex(self.batchNo),)
		return temp

	def toDict(self):
		temp = {}
		temp['hardwareVendorId'] = self.hardwareVendorId
		temp['hardwareType'] = self.hardwareType
		temp['hardwareSubType'] = self.hardwareSubType
		temp['hardwareMajVersion'] = self.hardwareMajVersion
		temp['hardwareMinVersion'] = self.hardwareMinVersion
		temp['hardwareStorageSize'] = self.hardwareStorageSize
		temp['hardwareProtocol'] = self.hardwareProtocol
		temp['softwareVendorId'] = self.softwareVendorId
		temp['softwareType'] = self.softwareType
		temp['softwareSubType'] = self.softwareSubType
		temp['softwareMajVersion'] = self.softwareMajVersion
		temp['softwareMinVersion'] = self.softwareMinVersion
		temp['softwareStorageSize'] = self.softwareStorageSize
		temp['softwareProtocol'] = self.softwareProtocol
		temp['UID'] = bytelist2hex(self.UID).upper()
		temp['batchNo'] = bytelist2hex(self.batchNo).upper()
		temp['cwProd'] = self.cwProd
		temp['yearProd'] = self.yearProd
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
		self.ReadAccess  = None
		self.WriteAccess = None
		self.ReadAndWriteAccess= None
		self.ChangeAccess= None

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
		temp['ReadAccess'] = self.ReadAccess
		temp['WriteAccess'] = self.WriteAccess
		temp['ReadAndWriteAccess'] = self.ReadAndWriteAccess
		temp['ChangeAccess'] = self.ChangeAccess
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

		self.FileType= None #DESFireFileType
		self.Encryption= None #DESFireFileEncryption
		self.Permissions= DESFireFilePermissions()
		# ----------------------------
		# used only for MDFT_STANDARD_DATA_FILE and MDFT_BACKUP_DATA_FILE
		self.FileSize= None #uint32_t
		# -----------------------------
		# used only for MDFT_VALUE_FILE_WITH_BACKUP
		self.LowerLimit= None #uint32_t
		self.UpperLimit= None #uint32_t
		self.LimitedCreditValue = None
		self.LimitedCreditEnabled= None #bool
		# -----------------------------
		# used only for MDFT_LINEAR_RECORD_FILE_WITH_BACKUP and MDFT_CYCLIC_RECORD_FILE_WITH_BACKUP
		self.RecordSize = None #uint32_t
		self.MaxNumberRecords = None #uint32_t
		self.CurrentNumberRecords = None 	#uint32_t

	def parse(self, data):
		self.FileType	= DESFireFileType(data[0])
		self.Encryption	= DESFireFileEncryption(data[1])
		self.Permissions.unpack(struct.unpack('>H',bytelist2hex(data[2:4]).decode('hex'))[0])
		
		if self.FileType == DESFireFileType.MDFT_LINEAR_RECORD_FILE_WITH_BACKUP:
			self.RecordSize = struct.unpack('<I', bytelist2hex(data[4:6] + [0x00, 0x00]).decode('hex'))[0]  
			self.MaxNumberRecords = struct.unpack('<I', bytelist2hex(data[6:8] + [0x00, 0x00]).decode('hex'))[0]
			self.CurrentNumberRecords = struct.unpack('<I', bytelist2hex(data[8:10] + [0x00, 0x00]).decode('hex'))[0]

		elif self.FileType == DESFireFileType.MDFT_STANDARD_DATA_FILE:
			self.FileSize = struct.unpack('<I', bytelist2hex(data[4:6] + [0x00, 0x00]).decode('hex'))[0]


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


class DesfireException(Exception):
	def __init__(self, status_code):
		self.cmd_sent = ''
		self.status_code = DESFireStatus(status_code)
		self.msg = DESFireStatus(status_code).name

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


		#SessionKey       = NULL;
		#LastAuthKeyNo    = NOT_AUTHENTICATED;
		#LastPN532Error   = 0;    
		#LastApplication = 0x000000; # No application selected

		#The PICC master key on an empty card is a simple DES key filled with 8 zeros
		#const byte ZERO_KEY[24] = {0};
		#DES2_DEFAULT_KEY.SetKeyData(ZERO_KEY,  8, 0); # simple DES
		#DES3_DEFAULT_KEY.SetKeyData(ZERO_KEY, 24, 0); # triple DES
		#AES_DEFAULT_KEY.SetKeyData(ZERO_KEY, 16, 0);

	@classmethod
	def wrap_command(cls, command, parameters=None):
		"""Wrap a command to native DES framing.
		:param command: Command byte
		:param parameters: Command parameters as list of bytes
		https:#github.com/greenbird/workshops/blob/master/mobile/Android/Near%20Field%20Communications/HelloWorldNFC%20Desfire%20Base/src/com/desfire/nfc/DesfireReader.java#L129
		"""
		if parameters:
			return [0x90, command, 0x00, 0x00, len(parameters)] + parameters + [0x00]
		else:
			return [0x90, command, 0x00, 0x00, 0x00]



	def communicate(self, apdu, autorecieve = True, isEncryptedComm = False):
		result = []
		while True:
			self.logger.debug("[+] Sending APDU : %s" % (bytelist2hex(apdu, separator = ' '),))
			response, sw1, status = self.reader.sendAPDU(apdu)
			self.logger.debug("[+] Card response: %s SW1: %x SW2: %x" % (bytelist2hex(response, separator = ' '), sw1, status))
			if sw1 != 0x91:
				raise DesfireException(status)
			if status not in [DESFireStatus.ST_Success.value, DESFireStatus.ST_NoChanges.value, DESFireStatus.ST_MoreFrames.value]:
				raise DesfireException(status)

			if self.isAuthenticated and len(response) > 8 and status == DESFireStatus.ST_Success.value and sw1 == 0x91:
				#after authentication, there is always an 8 bytes long CMAC coming from the card, to ensure message integrity
				#todo: verify CMAC
				RXCMAC = response[-8:]
				response = response[:-8]


			result += response

			if status != DESFireStatus.ST_MoreFrames.value or not autorecieve:
				break
			else:
				apdu = self.wrap_command(DESFireCommand.DF_INS_ADDITIONAL_FRAME.value)
				

		if isEncryptedComm:
			#todo: decrpyt recieved buffer with session key
			raise Excpetion('Not yet implemented!')
			

		return result

	def GetCardVersion(self):

		self.logger.debug('Getting card version info')
		cmd = self.wrap_command(DESFireCommand.DF_INS_GET_VERSION.value)
		cv = DESFireCardVersion()
		cv.parse(self.communicate(cmd))
		self.logger.debug(repr(cv)) 
		return cv
		


	def GetApplicationIDs(self):
		self.logger.debug("Enumerating all applications")
		appids = []
		cmd = self.wrap_command(DESFireCommand.DF_INS_GET_APPLICATION_IDS.value)
		raw_data = self.communicate(cmd)

		pointer = 0
		apps = []
		while pointer < len(raw_data):
			app_id = (raw_data[pointer] << 16) + (raw_data[pointer+1] << 8) + raw_data[pointer+2]
			self.logger.debug("Reading %d %08x", pointer, app_id)
			apps.append(app_id)
			pointer += 3

		return apps
		

	def SelectApplication(self, app_id):
		"""Choose application on a card on which all the following file commands will apply.
		:param app_id: 24-bit int
		:raise: :py:class:`desfire.protocol.DESFireCommunicationError` on any error
		"""
		# https:#github.com/greenbird/workshops/blob/master/mobile/Android/Near%20Field%20Communications/HelloWorldNFC%20Desfire%20Base/src/com/desfire/nfc/DesfireReader.java#L53
		
		self.logger.debug('Selecting application with AppID %s' % (app_id,))
		parameters = [
			(app_id >> 16) & 0xff,
			(app_id >> 8) & 0xff,
			(app_id >> 0) & 0xff,
		]

		cmd = self.wrap_command(DESFireCommand.DF_INS_SELECT_APPLICATION.value, parameters)
		self.communicate(cmd)
		#if new application is selected, authentication needs to be carried out again
		self.isAuthenticated = False
		self.lastSelectedApplication = app_id

	def GetKeySettings(self):
		#you must call selectapplication first!
		self.logger.debug('Getting key settings')

		cmd = self.wrap_command(DESFireCommand.DF_INS_GET_KEY_SETTINGS.value)
		raw_data = self.communicate(cmd)

		keysettings = calc_key_settings(raw_data[0]) #*pe_Settg = (DESFireKeySettings)u8_RetData[0];
		keycount =  raw_data[1] & 0x0F#*pu8_KeyCount = u8_RetData[1] & 0x0F;
		keytype = DESFireKeyType(raw_data[1] & 0xF0) #*pe_KeyType   = (DESFireKeyType)(u8_RetData[1] & 0xF0);

		self.logger.debug("Settings: %s, KeyCount: %d, KeyType: %s\r\n" % ('|'.join(a.name for a in keysettings), keycount, keytype))

		return keysettings, keycount, keytype

	def GetFileIDs(self):
		#you must call selectapplication first!
		self.logger.debug('Enumerating all files for the selected application')

		cmd = self.wrap_command(DESFireCommand.DF_INS_GET_FILE_IDS.value)
		raw_data = self.communicate(cmd)
		if len(raw_data) == 0:
			self.logger.debug("No files found")
		else:
			self.logger.debug("File ids: %s" % (bytelist2hex(raw_data),))
		return raw_data

	def GetFileSettings(self, fileid):
		#you must call selectapplication first!
		self.logger.debug('Getting file settings for file %s' % (fileid,))

		cmd = self.wrap_command(DESFireCommand.DF_INS_GET_FILE_SETTINGS.value, [fileid])
		raw_data = self.communicate(cmd)

		file_settings = DESFireFileSettings()
		file_settings.parse(raw_data)
		return file_settings

	def ReadFileData(self,fileid):
		self.logger.debug('Reading file data for file %s' % (fileid,))

		parameters = [fileid, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
		cmd = self.wrap_command(0xbd, parameters)

		buffer = self.communicate(cmd)
		self.logger.debug('File %s Data: ' % (fileid,bytelist2hex(buffer)))

		return buffer

	def FormatCard(self):
		self.logger.debug('Formatting card')
		cmd = self.wrap_command(DESFireCommand.DF_INS_FORMAT_PICC.value)
		raw_data = self.communicate(cmd)

	def CreateApplication(self, appid, keysettings, keycount, type):
		self.logger.debug('Creating application with appid: %x, ')
		#keysettings is a list of DESFireKeySettings
		#type is of type DESFireKeyType

		appid = [
			(appid >> 16) & 0xff,
			(appid >> 8) & 0xff,
			(appid >> 0) & 0xff,
		]

		params = appid + [calc_key_settings(keysettings), keycount|type.value]
		cmd = self.wrap_command(DESFireCommand.DF_INS_CREATE_APPLICATION.value, params)
		raw_data = self.communicate(cmd)
		#raw_data = self.communicate(cmd)

	def DeleteApplication(self, appid):
		self.logger.debug('Deleting application for AppID 0x%x', (appid))

		appid = [
			(appid >> 16) & 0xff,
			(appid >> 8) & 0xff,
			(appid >> 0) & 0xff,
		]
		params = appid
		cmd = self.wrap_command(DESFireCommand.DF_INS_DELETE_APPLICATION.value, params)
		raw_data = self.communicate(cmd)


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


	def toDict(self):
		temp = SmartCard.toDict(self)
		temp ['versioninfo'] = self.versioninfo.toDict()
		temp ['applications'] = []
		for app in self.applications:
			temp ['applications'].append(app.toDict())
		return temp

	def Authenticate(self, key_id, key, challenge = None):
		self.logger.debug('Authenticating')
		cmd = None
		keyType = key.GetKeyType()
		if keyType == DESFireKeyType.DF_KEY_AES:
			cmd = self.wrap_command(DESFireCommand.DFEV1_INS_AUTHENTICATE_AES.value, [key_id]) 
		elif keyType == DESFireKeyType.DF_KEY_2K3DES or keyType == DESFireKeyType.DF_KEY_3K3DES:
			cmd = self.wrap_command(DESFireCommand.DFEV1_INS_AUTHENTICATE_ISO.value, [key_id]) 
		else:
			raise Exception('Invalid key type!')


		raw_data = self.communicate(cmd, autorecieve = False)
		RndB_enc = raw_data
		#RndB_enc = hexstr2bytelist('5D 99 4C E0 85 F2 40 89')
		self.logger.debug( 'Random B (enc): ' + bytelist2hex(RndB_enc, separator = ' '))
		key.CiperInit()
		RndB = key.Decrypt(bytelist2hex(RndB_enc).decode('hex'))
		RndB = hex2bytelist(RndB)
		self.logger.debug( 'Random B (dec): ' + bytelist2hex(RndB, separator = ' '))
		RndB_rot = RotateBlockLeft(RndB)
		self.logger.debug( 'Random B (dec, rot): ' + bytelist2hex(RndB_rot, separator = ' '))

		if challenge != None:
			RndA = hex2bytelist(challenge)
		else:
			RndA = hex2bytelist(Random.get_random_bytes(8))
		self.logger.debug( 'Random A: ' + bytelist2hex(RndA, separator = ' '))
		RndAB = RndA + RndB_rot
		self.logger.debug( 'Random AB: ' + bytelist2hex(RndAB, separator = ' '))
		RndAB_enc = key.Encrypt(bytelist2hex(RndAB).decode('hex'))
		RndAB_enc = hex2bytelist(RndAB_enc)
		self.logger.debug( 'Random AB (enc): ' + bytelist2hex(RndAB_enc, separator = ' '))

		cmd = self.wrap_command(DESFireCommand.DF_INS_ADDITIONAL_FRAME.value, RndAB_enc)
		raw_data = self.communicate(cmd, autorecieve = False)
		#raw_data = hexstr2bytelist('91 3C 6D ED 84 22 1C 41')
		RndA_enc = raw_data
		self.logger.debug('Random A (enc): ' + bytelist2hex(RndA_enc, separator = ' '))
		RndA_dec = key.Decrypt(bytelist2hex(RndA_enc).decode('hex'))
		RndA_dec = hex2bytelist(RndA_dec)
		self.logger.debug( 'Random A (dec): ' + bytelist2hex(RndA_dec, separator = ' '))
		RndA_dec_rot = RotateBlockRight(RndA_dec)
		self.logger.debug( 'Random A (dec, rot): ' + bytelist2hex(RndA_dec_rot, separator = ' '))

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
			sessionKeyBytes = [a & 0b11111110 for a in sessionKeyBytes]


		###??????????????????????????????????????????????????????
		###if (pi_Key->GetKeyType() == DF_KEY_AES) mpi_SessionKey = &mi_AesSessionKey;
		###else                                    mpi_SessionKey = &mi_DesSessionKey;
	
		## now we have the session key, so we reinitialize the crypto!!!
		sessionKeyBytes = bytelist2hex(sessionKeyBytes).decode('hex')
		sessionKey = DESFireKey(sessionKeyBytes, keyType)
		sessionKey.CiperInit()
		sessionKey.GenerateCmacSubkeys()

		self.logger.debug( 'Cmac1: ' + sessionKey.Cmac1.encode('hex').upper())
		self.logger.debug( 'Cmac2: ' + sessionKey.Cmac2.encode('hex').upper())
		self.logger.debug( 'sessionKey: ' + sessionKey.keyBytes.encode('hex').upper())
		self.sessionKey = sessionKey
		return sessionKey

	def	GetKeyVersion(self, keyNo):
		self.logger.debug('Getting key version for keyid %x' %(keyNo,))

		cmd = self.wrap_command(DESFireCommand.DF_INS_GET_KEY_VERSION.value, [keyNo])
		raw_data = self.communicate(cmd)
		self.logger.debug('Got key version 0x%s for keyid %x' %(bytelist2hex(raw_data),keyNo))
		return raw_data

	def ChangeKeySettings(self, newKeySettings):
		self.logger.debug('Changing key settings to %s' %('|'.join(a.name for a in newKeySettings),))
		cmd = self.wrap_command(DESFireCommand.DF_INS_CHANGE_KEY_SETTINGS.value, [calc_key_settings(newKeySettings)])
		raw_data = self.communicate(cmd)

	def ChangeKey(self, keyNo, newKey, curKey):
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
			keyData_xor = XOR(newKey.keyBytes, curKey.keyBytes)
			cryptogram += keyData_xor
		else:
			cryptogram += newKey.keyBytes
		 
		if newKey.keyType == DESFireKeyType.DF_KEY_AES:
			cryptogram += int2hex(newKey.keyVersion)

		#self.logger.debug( (int2hex(DESFireCommand.DF_INS_CHANGE_KEY.value) + int2hex(keyNo) + cryptogram).encode('hex'))
		Crc = self.DESFireCRC32(int2hex(DESFireCommand.DF_INS_CHANGE_KEY.value) + int2hex(keyNo), cryptogram)
		self.logger.debug('Crc        : ' + hex2hexstr(Crc))
		Crc_rev = Crc[::-1]
		cryptogram += Crc_rev

		if not isSameKey:
			CrcNew = self.DESFireCRC32(newKey.keyBytes)
			self.logger.debug('Crc New Key: ' + hex2hexstr(CrcNew))
			cryptogram += CrcNew[::-1]

		self.logger.debug('Cryptogram      : ' + hex2hexstr(cryptogram))
		cryptogram_enc = self.sessionKey.PaddedEncrypt(cryptogram)
		self.logger.debug('Cryptogram (enc): ' + hex2hexstr(cryptogram_enc))

		params = [keyNo] + hex2bytelist(cryptogram_enc)
		cmd = self.wrap_command(DESFireCommand.DF_INS_CHANGE_KEY.value, params)
		raw_data = self.communicate(cmd)

		#If we changed the currently active key, then re-auth is needed!
		if isSameKey:
			self.isAuthenticated = False
			self.sessionKey = None

		return

	def DESFireCRC32(self,cmd, params = None):
		CRC = 0xFFFFFFFF
		CRC = self.CalcCrc32(cmd, CRC);
		if params != None:
			CRC = self.CalcCrc32(params, CRC);
		return int2hex(CRC)

	def CalcCrc32(self, data, initVal):
		#data = data in hex
		#initVal = integer (or long)
		for b in hex2bytelist(data):
			initVal = (initVal ^ b)
			for p in range(8):
				bit = (initVal & 0x01) > 0
				initVal = (initVal >> 1)
				if bit:
					initVal = (initVal ^ 0xEDB88320)
        
		return initVal




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

		

	def CiperInit(self):
		#todo assert on key length!
		if self.keyType == DESFireKeyType.DF_KEY_AES:
			#AES is used
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
		#print (data + '\x00'*(len(data) % self.CipherBlocksize)).encode('hex')
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

	def GenerateCmacSubkeys(self):
		### THIS PART IS NOT WORKING CORRECTLY!!!
		R = 0x87
		if self.CipherBlocksize == 8:
			R = 0x1B

		data = '\x00'*16
		self.ClearIV()
		data = self.Decrypt(data)
		self.Cmac1 = BitShiftLeft(data, self.CipherBlocksize)
		if (hex2int(data[0]) & 0x80):
			self.Cmac1 = self.Cmac1[:-1] + int2hex(hex2int(self.Cmac1[-1]) ^ R)

		self.Cmac2 = BitShiftLeft(self.Cmac1, self.CipherBlocksize)
		if (hex2int(self.Cmac1[0]) & 0x80):
			self.Cmac2  = self.Cmac2 [:-1] + int2hex(hex2int(self.Cmac2 [-1]) ^ R)


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
		except DesfireException as e:
			if e.status_code == DESFireStatus.ST_AuthentError:
				pass

		try:
			for fileid in card.GetFileIDs():
				try:
					file = DESFireFile(self.appid, fileid)
					file.enumerate(card)
					self.files.append(file)
				except DesfireException as e:
					if e.status_code == DESFireStatus.ST_AuthentError:
						self.files.append(DESFireFile(self.appid, fileid))
						pass
		
		except DesfireException as e:
			if e.status_code == DESFireStatus.ST_AuthentError:
				self.files = None
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
		except DesfireException as e:
			if e.status_code == DESFireStatus.ST_AuthentError:
				pass

		try:
			for fileid in card.GetFileIDs():
				self.filedata = card.ReadFileData(fileid)		
		except DesfireException as e:
			if e.status_code == DESFireStatus.ST_AuthentError:
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

if __name__ == '__main__':
	import sys
	import json
	import pprint 

	global logger

	logging.basicConfig(level=logging.DEBUG)
	logger = logging.getLogger(__name__)

	reader = PCSCReader()
	#reader = DummyReader()
	reader.connect()
	card = Desfire(reader)
	#card.GetCardVersion()

	#card.security_check()
	#card.enumerate()

	#pp = pprint.PrettyPrinter(indent=4)
	#pp.pprint(card.toDict())
	#print json.dumps(card.toDict(), indent = 4, sort_keys = True)
	newKeySettings = [DESFireKeySettings.KS_ALLOW_CHANGE_MK, DESFireKeySettings.KS_LISTING_WITHOUT_MK,
		DESFireKeySettings.KS_CREATE_DELETE_WITHOUT_MK,DESFireKeySettings.KS_CONFIGURATION_CHANGEABLE]

	#keyBytes = bytelist2hex([0x00] * 8).decode('hex')
	#keyType = DESFireKeyType.DF_KEY_2K3DES

	#key = DESFireKey(keyBytes, keyType)
	
	#ORIGINAL!::::#
	key = DESFireKey(hexstr2hex('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'), DESFireKeyType.DF_KEY_2K3DES)
	#key = DESFireKey(hexstr2hex('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'), DESFireKeyType.DF_KEY_3K3DES)
	

	newKey = DESFireKey(hexstr2hex('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'), DESFireKeyType.DF_KEY_3K3DES)

	#sessionKey = DESFireKey(hexstr2hex('36 C4 F8 BE 30 6E 6C 76 AC 22 9E 8C F8 24 BA 30 32 50 D4 AA 64 36 56 A2'), DESFireKeyType.DF_KEY_3K3DES)
	#sessionKey.CiperInit()

	try:
		card.Authenticate(0, key)
		#card.FormatCard()
		#card.CreateApplication(0xFFA155, [DESFireKeySettings.KS_ALLOW_CHANGE_MK, DESFireKeySettings.KS_LISTING_WITHOUT_MK,
		# DESFireKeySettings.KS_CREATE_DELETE_WITHOUT_MK,DESFireKeySettings.KS_CONFIGURATION_CHANGEABLE], 1, DESFireKeyType.DF_KEY_2K3DES)
		#card.GetApplicationIDs()
		#card.enumerate()
		#card.GetKeyVersion(0)
		
		#card.isAuthenticated = True
		#card.lastAuthKeyNo = 0
		#card.sessionKey = sessionKey
		
		card.ChangeKey(0,newKey,key)
	except DesfireException as e:
		print 'Exception: ' + e.msg