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
from readers import PCSCReader


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

		self.UID   = data[14:20]        # The serial card number
		self.batchNo     = data[20:25]      # The batch number
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
		self.ReadAccess         = ((data >> 12) & 0x0F)
		self.WriteAccess        = ((data >>  8) & 0x0F)
		self.ReadAndWriteAccess = ((data >>  4) & 0x0F)
		self.ChangeAccess       = ((data      ) & 0x0F)

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
		temp['FileType'] = self.FileType
		temp['Encryption'] = self.Encryption
		temp['Permissions'] = self.Permissions.toDict()
		temp['LowerLimit'] = self.LowerLimit
		temp['UpperLimit'] = self.UpperLimit
		temp['LimitedCreditValue'] = self.LimitedCreditValue
		temp['LimitedCreditEnabled'] = self.LimitedCreditEnabled
		temp['RecordSize'] = self.RecordSize
		temp['MaxNumberRecords'] = self.MaxNumberRecords
		temp['CurrentNumberRecords'] = self.CurrentNumberRecords
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

class Desfire():

	def __init__(self, reader, logger=None):

		self.reader = reader
		if logger:
			self.logger = logger
		else:
			self.logger = _logger

		self.versioninfo = None
		self.appid = 0x000000
		self.masterkeysettings = None
		self.keycount = None
		self.keytype = None

		self.applications = []
		self.files = []


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



	def communicate(self, apdu):
		result = []

		while True:
			self.logger.debug("[+] Sending APDU: %s" % (bytelist2hex(apdu),))
			response, sw1, status = self.reader.sendAPDU(apdu)
			self.logger.debug("[+] Card response: %s SW1: %x SW2: %x" % (bytelist2hex(response), sw1, status))
			if sw1 != 0x91:
				raise DesfireException(status)
			if status not in [DESFireStatus.ST_Success.value, DESFireStatus.ST_NoChanges.value, DESFireStatus.ST_MoreFrames.value]:
				raise DesfireException(status)


			result += response

			if status != DESFireStatus.ST_MoreFrames.value:
				break
			else:
				apdu = self.wrap_command(DESFireCommand.DF_INS_ADDITIONAL_FRAME.value)

		return result

	def GetCardVersion(self):

		self.logger.debug('Getting card version info')
		cmd = self.wrap_command(DESFireCommand.DF_INS_GET_VERSION.value)
		cv = DESFireCardVersion()
		cv.parse(self.communicate(cmd))
		self.logger.debug(repr(cv)) 


	def GetApplicationIDs(self):
		self.logger.debug("Enumerating all applications")
		appids = []
		cmd = self.wrap_command(DESFireCommand.DF_INS_GET_APPLICATION_IDS.value)
		raw_data = self.communicate(cmd)
		return self.parse_application_list(raw_data)


	def parse_application_list(self, resp):
		"""Handle response for command 0x6a list applications.
		DESFire application ids are 24-bit integers.
		:param resp: DESFire response as byte array
		:return: List of parsed application ids
		"""
		pointer = 0
		apps = []
		while pointer < len(resp):
			app_id = (resp[pointer] << 16) + (resp[pointer+1] << 8) + resp[pointer+2]
			self.logger.debug("Reading %d %08x", pointer, app_id)
			apps.append(app_id)
			pointer += 3

		return apps

	def select_application(self, app_id):
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

	def GetKeySettings(self):
		#you must call selectapplication first!
		self.logger.debug('Getting key settings')

		cmd = self.wrap_command(DESFireCommand.DF_INS_GET_KEY_SETTINGS.value)
		raw_data = self.communicate(cmd)

		print bin(raw_data[0])
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

	def ReadFileData(self,file_id):
		self.logger.debug('Reading file data for file %s' % (fileid,))

		parameters = [file_id, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
		cmd = self.wrap_command(0xbd, parameters)

		buffer = self.communicate(cmd)
		print buffer

		return buffer

	def Authenticate(self, key_id, key):
		raise Exception('Not yet implemented :(')
		#self.logger.debug('Authenticating')


	def enumerate(self):
		self.versioninfo = self.GetCardVersion()
		### this is for the ROOT dir (main app)
		app = DESFireApplication(0x000000)  
		app.enumerate(self)
		self.masterkeysettings, self.keycount, self.keytype = app.keysettings
		self.files = app.files

		### actual apps now
		for appid in self.GetApplicationIDs():
			app = DESFireApplication()
			app.enumerate(appid)
			self.applications.append(app)

	def security_check(self):
		#check for UID randomization, by calling getversion 2 times and comparing the UIDs
		#check for Masterkey settings, need evaluation table for that
		#check for application key settings, need evaulation table for that
		#check for unprotected apps/files, need evalua... no, actually we dont
		return None


	def toDict(self):
		temp = {}
		temp ['versioninfo'] = self.versioninfo.toDict()
		temp ['appid'] = self.appid.encode('hex')
		temp ['masterkeysettings'] = self.masterkeysettings
		temp ['keycount'] = self.keycount
		temp ['keytype'] = self.keytype
		temp ['applications'] = []
		for app in self.applications:
			temp ['applications'].append(app.toDict())

		temp ['files'] = []
		for file in self.files:
			temp['files'].append(file.toDict())
		return temp

ENUM_ERROR_AUTHNEEDED = 'AUTHNEEDED'

class DESFireApplication:
	def __init__(self, appid):
		self.appid = appid
		self.files = []
		self.keysettings = None
		self.keycount = None
		self.keytype = None

	def enumerate(self, card):
		card.select_application(self.appid)
		try:
			#getting the key settings
			self.keysettings, self.keycount, self.keytype = card.GetKeySettings()
		except DesfireException as e:
			if e.status_code == DESFireStatus.ST_AuthentError:
				self.keysettings, self.keycount, self.keytype = (ENUM_ERROR_AUTHNEEDED,ENUM_ERROR_AUTHNEEDED,ENUM_ERROR_AUTHNEEDED)
				pass

		try:
			for fileid in card.GetFileIDs():
				file = DESFireFile(self.appid, fileid)
				file.enumerate(self)
				self.files.append(file)
		except DesfireException as e:
			if e.status_code == DESFireStatus.ST_AuthentError:
				self.files.append(DESFireFile(self.appid, fileid))
				pass

	def toDict(self):
		temp = {}
		temp['appid'] = self.appid.encode('hex')
		temp['files'] = []
		for file in self.files:
			temp['files'] = file.toDict()
		temp['keysettings'] = []
		if self.keysettings != ENUM_ERROR_AUTHNEEDED:
			for keysetting in self.keysettings:
				temp['keysettings'] = keysetting.name 
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
		card.select_application(self.appid)
		try:
			for fileid in card.GetFileIDs():
				self.fielsettings = card.GetFileSettings(fileid)		
		except DesfireException as e:
			if e.status_code == DESFireStatus.ST_AuthentError:
				self.fielsettings = ENUM_ERROR_AUTHNEEDED
				pass

		try:
			for fileid in card.GetFileIDs():
				self.filedata = card.ReadFileData(fileid)		
		except DesfireException as e:
			if e.status_code == DESFireStatus.ST_AuthentError:
				self.filedata = ENUM_ERROR_AUTHNEEDED
				pass

	def toDict(self):
		temp = {}
		temp['appid'] = self.appid.encode('hex')
		temp['fileid'] = self.fileid.encode('hex')
		if self.fielsettings != ENUM_ERROR_AUTHNEEDED:
			temp['fielsettings'] = self.fielsettings.toDict()
			temp['filedata'] = self.filedata.encode('hex')
		return temp


def bytelist2hex(data):
	return ''.join('{:02x}'.format(x) for x in data)

if __name__ == '__main__':
	import sys
	global logger

	logging.basicConfig(level=logging.DEBUG)
	logger = logging.getLogger(__name__)

	reader = PCSCReader()
	reader.connect()
	card = Desfire(reader)
	card.GetCardVersion()

	#card.security_check()
	#card.enumerate()