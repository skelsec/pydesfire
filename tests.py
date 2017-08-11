from enum import Enum
import logging
import struct
from readers import DummyReader, PCSCReader
from pydesfire import Desfire, DESFireKeyType, DESFireKey, DESFireKeySettings, DesfireException
from cards import SmartCardTypes, SmartCard
from utils import *



def AuthTest_DES():
	print 'AuthTest_DES'

	reader = DummyReader()
	reader.connect()
	
	#RndB_enc
	reader.addResponse((hexstr2bytelist('5D 99 4C E0 85 F2 40 89'), 0x91, 0xAF))
	reader.addResponse((hexstr2bytelist('91 3C 6D ED 84 22 1C 41'), 0x91, 0x00))
	card = Desfire(reader)

	key = DESFireKey(hexstr2hex('00 00 00 00 00 00 00 00'), DESFireKeyType.DF_KEY_2K3DES)
	sessionKey = card.Authenticate(0,key, challenge = hexstr2hex('84 9B 36 C5 F8 BF 4A 09'))
	assert sessionKey.keyBytes == hexstr2hex('84 9A 36 C4 4E D0 B6 58')

	print 'AuthTest_DES Succsess'


def AuthTest_2DES():
	print 'AuthTest_2DES'
	"""
		*** Authenticate(KeyNo= 0, Key= 00 10 20 31 40 50 60 70 80 90 A0 B0 B0 A0 90 80 (2K3DES))
		Sending:  00 00 FF 05 FB <D4 40 01 1A 00> D1 00
		Response: 00 00 FF 0C F4 <D5 41 00 AF B2 95 57 99 26 15 5A E3> 8C 00 AA AA AA AA AA AA AA AA
		* RndB_enc:  B2 95 57 99 26 15 5A E3
		* RndB:      BC D8 29 97 47 33 2D AF
		* RndB_rot:  D8 29 97 47 33 2D AF BC
		* RndA:      53 0E 3D 90 F7 A2 01 C4
		* RndAB:     53 0E 3D 90 F7 A2 01 C4 D8 29 97 47 33 2D AF BC
		* RndAB_enc: 70 F3 49 74 0C 94 5D AE 15 9B A9 FE DB CC 46 1A
		Sending:  00 00 FF 14 EC <D4 40 01 AF 70 F3 49 74 0C 94 5D AE 15 9B A9 FE DB CC 46 1A> 13 00
		Response: 00 00 FF 0C F4 <D5 41 00 00 B8 FD 7F E5 6B 24 1F C4> 5F 00
		* RndA_enc:  B8 FD 7F E5 6B 24 1F C4
		* RndA_dec:  0E 3D 90 F7 A2 01 C4 53
		* RndA_rot:  0E 3D 90 F7 A2 01 C4 53
		* SessKey:   52 0E 3C 90 BC D8 28 96 F6 A2 00 C4 46 32 2C AE (2K3DES)
	"""

	reader = DummyReader()
	reader.connect()
	
	#RndB_enc
	reader.addResponse((hexstr2bytelist('B2 95 57 99 26 15 5A E3'), 0x91, 0xAF))
	reader.addResponse((hexstr2bytelist('B8 FD 7F E5 6B 24 1F C4'), 0x91, 0x00))
	card = Desfire(reader)

	key = DESFireKey(hexstr2hex('00 10 20 31 40 50 60 70 80 90 A0 B0 B0 A0 90 80'), DESFireKeyType.DF_KEY_2K3DES)
	sessionKey = card.Authenticate(0,key, challenge = hexstr2hex('53 0E 3D 90 F7 A2 01 C4'))
	print sessionKey.keyBytes.encode('hex')
	assert sessionKey.keyBytes == hexstr2hex('52 0E 3C 90 BC D8 28 96 F6 A2 00 C4 46 32 2C AE')

	print 'AuthTest_2DES Succsess'

def AuthTest_3DES():
	print 'AuthTest_3DES'
	"""
		*** Authenticate(KeyNo= 0, Key= 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (3K3DES))
		Sending:  00 00 FF 05 FB <D4 40 01 1A 00> D1 00
		Response: 00 00 FF 14 EC <D5 41 00 AF BC 1C 57 0B C9 48 15 61 87 13 23 64 E4 DC E1 76> 42 00
		* RndB_enc:  BC 1C 57 0B C9 48 15 61 87 13 23 64 E4 DC E1 76
		* RndB:      31 6E 6D 76 A4 49 F9 25 BA 30 4F B2 65 36 56 A2
		* RndB_rot:  6E 6D 76 A4 49 F9 25 BA 30 4F B2 65 36 56 A2 31
		* RndA:      36 C5 F8 BF 4A 09 AC 23 9E 8D A0 C7 32 51 D4 AB
		* RndAB:     36 C5 F8 BF 4A 09 AC 23 9E 8D A0 C7 32 51 D4 AB 6E 6D 76 A4 49 F9 25 BA 30 4F B2 65 36 56 A2 31
		* RndAB_enc: DD DC 9A 77 59 7F 03 A4 0C 7F AA 36 2F 45 A8 EA DB E4 6A 11 5D 98 19 8C BF 36 A6 E5 1B 39 D8 7C
		Sending:  00 00 FF 24 DC <D4 40 01 AF DD DC 9A 77 59 7F 03 A4 0C 7F AA 36 2F 45 A8 EA DB E4 6A 11 5D 98 19 8C BF 36 A6 E5 1B 39 D8 7C> 86 00
		Response: 00 00 FF 14 EC <D5 41 00 00 72 44 D9 35 ED 9A 13 06 CD 8C 84 1A 7C 1D E3 9A> 79 00
		* RndA_enc:  72 44 D9 35 ED 9A 13 06 CD 8C 84 1A 7C 1D E3 9A
		* RndA_dec:  C5 F8 BF 4A 09 AC 23 9E 8D A0 C7 32 51 D4 AB 36
		* RndA_rot:  C5 F8 BF 4A 09 AC 23 9E 8D A0 C7 32 51 D4 AB 36
		* SessKey:   36 C4 F8 BE 30 6E 6C 76 AC 22 9E 8C F8 24 BA 30 32 50 D4 AA 64 36 56 A2 (3K3DES)
	"""
	reader = DummyReader()
	reader.connect()
	
	#RndB_enc
	reader.addResponse((hexstr2bytelist('BC 1C 57 0B C9 48 15 61 87 13 23 64 E4 DC E1 76'), 0x91, 0xAF))
	reader.addResponse((hexstr2bytelist('72 44 D9 35 ED 9A 13 06 CD 8C 84 1A 7C 1D E3 9A'), 0x91, 0x00))
	card = Desfire(reader)

	key = DESFireKey(hexstr2hex('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'), DESFireKeyType.DF_KEY_3K3DES)
	sessionKey = card.Authenticate(0,key, challenge = hexstr2hex('36 C5 F8 BF 4A 09 AC 23 9E 8D A0 C7 32 51 D4 AB'))
	print sessionKey.keyBytes.encode('hex')
	assert sessionKey.keyBytes == hexstr2hex('36 C4 F8 BE 30 6E 6C 76 AC 22 9E 8C F8 24 BA 30 32 50 D4 AA 64 36 56 A2')

	print 'AuthTest_3DES Succsess'
def AuthTest_AES():
	print 'AuthTest_AES'
	"""
		*** Authenticate(KeyNo= 0, Key= 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (AES))
		Sending:  00 00 FF 05 FB <D4 40 01 AA 00> 41 00
		Response: 00 00 FF 14 EC <D5 41 00 AF B9 69 FD FE 56 FD 91 FC 9D E6 F6 F2 13 B8 FD 1E> ED 00
		* RndB_enc:  B9 69 FD FE 56 FD 91 FC 9D E6 F6 F2 13 B8 FD 1E
		* RndB:      C0 5D DD 71 4F D7 88 A6 B7 B7 54 F3 C4 D0 66 E8
		* RndB_rot:  5D DD 71 4F D7 88 A6 B7 B7 54 F3 C4 D0 66 E8 C0
		* RndA:      F4 4B 26 F5 68 6F 3A 39 1C D3 8E BD 10 77 22 81
		* RndAB:     F4 4B 26 F5 68 6F 3A 39 1C D3 8E BD 10 77 22 81 5D DD 71 4F D7 88 A6 B7 B7 54 F3 C4 D0 66 E8 C0
		* RndAB_enc: 36 AA D7 DF 6E 43 6B A0 8D 18 61 38 30 A7 0D 5A D4 3E 3D 3F 4A 8D 47 54 1E EE 62 3A 93 4E 47 74
		Sending:  00 00 FF 24 DC <D4 40 01 AF 36 AA D7 DF 6E 43 6B A0 8D 18 61 38 30 A7 0D 5A D4 3E 3D 3F 4A 8D 47 54 1E EE 62 3A 93 4E 47 74> 2A 00
		Response: 00 00 FF 14 EC <D5 41 00 00 80 0D B6 80 BC 14 6B D1 21 D6 57 8F 2D 2E 20 59> 6A 00
		* RndA_enc:  80 0D B6 80 BC 14 6B D1 21 D6 57 8F 2D 2E 20 59
		* RndA_dec:  4B 26 F5 68 6F 3A 39 1C D3 8E BD 10 77 22 81 F4
		* RndA_rot:  4B 26 F5 68 6F 3A 39 1C D3 8E BD 10 77 22 81 F4
		* SessKey:   F4 4B 26 F5 C0 5D DD 71 10 77 22 81 C4 D0 66 E8 (AES)
	"""
	reader = DummyReader()
	reader.connect()
	
	#RndB_enc
	reader.addResponse((hexstr2bytelist('B9 69 FD FE 56 FD 91 FC 9D E6 F6 F2 13 B8 FD 1E'), 0x91, 0xAF))
	reader.addResponse((hexstr2bytelist('80 0D B6 80 BC 14 6B D1 21 D6 57 8F 2D 2E 20 59'), 0x91, 0x00))
	card = Desfire(reader)

	key = DESFireKey(hexstr2hex('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'), DESFireKeyType.DF_KEY_AES)
	sessionKey = card.Authenticate(0,key, challenge = hexstr2hex('F4 4B 26 F5 68 6F 3A 39 1C D3 8E BD 10 77 22 81'))
	print sessionKey.keyBytes.encode('hex')
	assert sessionKey.keyBytes == hexstr2hex('F4 4B 26 F5 C0 5D DD 71 10 77 22 81 C4 D0 66 E8')

	print 'AuthTest_AES Succsess'


def AuthTest_AES2():
	print 'AuthTest_AES2'
	"""
	*** Authenticate(KeyNo= 1, Key= 10 18 20 28 30 38 40 48 50 58 60 68 70 78 80 88 (AES))
	Sending:  00 00 FF 05 FB <D4 40 01 AA 01> 40 00
	Response: 00 00 FF 14 EC <D5 41 00 AF B3 51 CB 24 65 D4 F3 3A C6 27 FD 6E 87 A1 68 F2> 08 00
	* RndB_enc:  B3 51 CB 24 65 D4 F3 3A C6 27 FD 6E 87 A1 68 F2
	* RndB:      62 6F FB D4 5C AF 33 4A CC A4 55 99 30 4F 5B 17
	* RndB_rot:  6F FB D4 5C AF 33 4A CC A4 55 99 30 4F 5B 17 62
	* RndA:      40 E7 D2 71 74 CB A6 75 E8 EF BA B9 9C 53 0E 3D
	* RndAB:     40 E7 D2 71 74 CB A6 75 E8 EF BA B9 9C 53 0E 3D 6F FB D4 5C AF 33 4A CC A4 55 99 30 4F 5B 17 62
	* RndAB_enc: 04 4B 6C AC 34 3A 08 65 89 51 49 64 9C A8 DD E1 F5 AC 4E C6 7B D2 08 90 0A F0 2F 04 9E 05 F0 B0
	Sending:  00 00 FF 24 DC <D4 40 01 AF 04 4B 6C AC 34 3A 08 65 89 51 49 64 9C A8 DD E1 F5 AC 4E C6 7B D2 08 90 0A F0 2F 04 9E 05 F0 B0> 67 00
	Response: 00 00 FF 14 EC <D5 41 00 00 A2 EE 14 4B 10 12 FB EB 7B 2F 11 13 2D 95 A4 54> 6B 00
	* RndA_enc:  A2 EE 14 4B 10 12 FB EB 7B 2F 11 13 2D 95 A4 54
	* RndA_dec:  E7 D2 71 74 CB A6 75 E8 EF BA B9 9C 53 0E 3D 40
	* RndA_rot:  E7 D2 71 74 CB A6 75 E8 EF BA B9 9C 53 0E 3D 40
	* SessKey:   40 E7 D2 71 62 6F FB D4 9C 53 0E 3D 30 4F 5B 17 (AES)
	"""

	reader = DummyReader()
	reader.connect()
	
	#RndB_enc
	reader.addResponse((hexstr2bytelist('B3 51 CB 24 65 D4 F3 3A C6 27 FD 6E 87 A1 68 F2'), 0x91, 0xAF))
	reader.addResponse((hexstr2bytelist('A2 EE 14 4B 10 12 FB EB 7B 2F 11 13 2D 95 A4 54'), 0x91, 0x00))
	card = Desfire(reader)

	key = DESFireKey(hexstr2hex('10 18 20 28 30 38 40 48 50 58 60 68 70 78 80 88'), DESFireKeyType.DF_KEY_AES)
	sessionKey = card.Authenticate(0,key, challenge = hexstr2hex('40 E7 D2 71 74 CB A6 75 E8 EF BA B9 9C 53 0E 3D'))
	print sessionKey.keyBytes.encode('hex')
	assert sessionKey.keyBytes == hexstr2hex('40 E7 D2 71 62 6F FB D4 9C 53 0E 3D 30 4F 5B 17')

	print 'AuthTest_AES2 Succsess'

def ChangeKeyTest_DES():
	return None


def ChangeKeyTest_2K3DES():
	print 'ChangeKeyTest_2K3DES'
	"""
	*** ChangeKey(KeyNo= 0)
	* SessKey IV:  00 00 00 00 00 00 00 00
	* New Key:     00 10 20 31 40 50 60 70 80 90 A0 B0 B0 A0 90 80 (2K3DES)
	* CRC Crypto:  0x5001FFC5
	* Cryptogram:  00 10 20 31 40 50 60 70 80 90 A0 B0 B0 A0 90 80 C5 FF 01 50 00 00 00 00
	* CryptogrEnc: BE DE 0F C6 ED 34 7D CF 0D 51 C7 17 DF 75 D9 7D 2C 5A 2B A6 CA C7 47 9D
	Sending:  00 00 FF 1D E3 <D4 40 01 C4 00 BE DE 0F C6 ED 34 7D CF 0D 51 C7 17 DF 75 D9 7D 2C 5A 2B A6 CA C7 47 9D> 97 00
	Response: 00 00 FF 04 FC <D5 41 00 00> EA 00 AA AA AA AA AA AA AA AA
	"""

	reader = DummyReader()
	reader.connect()
	reader.addResponse(('', 0x91, 0x00))
	reader.addExpectedRequest(hexstr2bytelist('90 C4 00 00 19 00 BE DE 0F C6 ED 34 7D CF 0D 51 C7 17 DF 75 D9 7D 2C 5A 2B A6 CA C7 47 9D 00'))
	card = Desfire(reader)

	oldKey = DESFireKey(hexstr2hex('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'), DESFireKeyType.DF_KEY_2K3DES)
	newKey = DESFireKey(hexstr2hex('00 10 20 31 40 50 60 70 80 90 A0 B0 B0 A0 90 80'), DESFireKeyType.DF_KEY_2K3DES)
	sessionKey = DESFireKey(hexstr2hex('C8 6C E2 5E 4C 64 7E 56'), DESFireKeyType.DF_KEY_2K3DES)

	sessionKey.CiperInit()

	card.isAuthenticated = True
	card.lastAuthKeyNo = 0
	card.sessionKey = sessionKey

	card.ChangeKey(0,newKey,oldKey)
	print 'ChangeKeyTest_2K3DES Succsess'

def ChangeKeyTest_3K3DES():
	print 'ChangeKeyTest_3K3DES'
	"""
	*** ChangeKey(KeyNo= 0)
	* SessKey IV:  00 00 00 00 00 00 00 00
	* New Key:     00 10 20 31 40 50 60 70 80 90 A0 B0 B0 A0 90 80 70 60 50 40 30 20 10 00 (3K3DES)
	* CRC Crypto:  0xA2003ED6
	* Cryptogram:  00 10 20 31 40 50 60 70 80 90 A0 B0 B0 A0 90 80 70 60 50 40 30 20 10 00 D6 3E 00 A2 00 00 00 00
	* CryptogrEnc: F4 F8 65 F3 18 CB 9D E8 0B 2B 16 51 45 02 1F 4F 3A FE F1 24 4F EA 42 FC 99 77 26 FD E7 50 74 1D
	Sending:  00 00 FF 25 DB <D4 40 01 C4 00 F4 F8 65 F3 18 CB 9D E8 0B 2B 16 51 45 02 1F 4F 3A FE F1 24 4F EA 42 FC 99 77 26 FD E7 50 74 1D> 6A 00
	Response: 00 00 FF 04 FC <D5 41 00 00> EA 00 AA AA AA AA AA AA AA AA
	"""

	reader = DummyReader()
	reader.connect()
	reader.addResponse(('', 0x91, 0x00))
	reader.addExpectedRequest(hexstr2bytelist('90 C4 00 00 21 00 F4 F8 65 F3 18 CB 9D E8 0B 2B 16 51 45 02 1F 4F 3A FE F1 24 4F EA 42 FC 99 77 26 FD E7 50 74 1D 00'))
	card = Desfire(reader)

	oldKey = DESFireKey(hexstr2hex('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'), DESFireKeyType.DF_KEY_3K3DES)
	newKey = DESFireKey(hexstr2hex('00 10 20 31 40 50 60 70 80 90 A0 B0 B0 A0 90 80 70 60 50 40 30 20 10 00'), DESFireKeyType.DF_KEY_3K3DES)
	sessionKey = DESFireKey(hexstr2hex('36 C4 F8 BE 30 6E 6C 76 AC 22 9E 8C F8 24 BA 30 32 50 D4 AA 64 36 56 A2'), DESFireKeyType.DF_KEY_3K3DES)

	sessionKey.CiperInit()

	card.isAuthenticated = True
	card.lastAuthKeyNo = 0
	card.sessionKey = sessionKey

	card.lastSelectedApplication = 0x00DE24

	card.ChangeKey(0,newKey,oldKey)
	print 'ChangeKeyTest_3K3DES Succsess'

def ChangeKeyTest_AES():
	print 'ChangeKeyTest_AES'
	"""
	*** ChangeKey(KeyNo= 0)
	* SessKey IV:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	* New Key:     00 10 20 30 40 50 60 70 80 90 A0 B0 B0 A0 90 80 (AES)
	* CRC Crypto:  0x6BE6C6D2
	* Cryptogram:  00 10 20 30 40 50 60 70 80 90 A0 B0 B0 A0 90 80 10 D2 C6 E6 6B 00 00 00 00 00 00 00 00 00 00 00
	* CryptogrEnc: E9 F8 5E 21 94 96 C2 B5 8C 10 90 DC 39 35 FA E9 E8 40 CF 61 B3 83 D9 53 19 46 25 6B 1F 11 0C 10
	Sending:  00 00 FF 25 DB <D4 40 01 C4 00 E9 F8 5E 21 94 96 C2 B5 8C 10 90 DC 39 35 FA E9 E8 40 CF 61 B3 83 D9 53 19 46 25 6B 1F 11 0C 10> D8 00
	Response: 00 00 FF 04 FC <D5 41 00 00> EA 00 AA AA AA AA AA AA AA AA
	"""

	reader = DummyReader()
	reader.connect()
	reader.addResponse(('', 0x91, 0x00))
	reader.addExpectedRequest(hexstr2bytelist('90 C4 00 00 21 00 E9 F8 5E 21 94 96 C2 B5 8C 10 90 DC 39 35 FA E9 E8 40 CF 61 B3 83 D9 53 19 46 25 6B 1F 11 0C 10 00'))
	card = Desfire(reader)

	oldKey = DESFireKey(hexstr2hex('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'), DESFireKeyType.DF_KEY_AES)
	newKey = DESFireKey(hexstr2hex('00 10 20 30 40 50 60 70 80 90 A0 B0 B0 A0 90 80'), DESFireKeyType.DF_KEY_AES)
	newKey.keyVersion = 0x10
	sessionKey = DESFireKey(hexstr2hex('F4 4B 26 F5 C0 5D DD 71 10 77 22 81 C4 D0 66 E8'), DESFireKeyType.DF_KEY_AES)

	sessionKey.CiperInit()

	card.isAuthenticated = True
	card.lastAuthKeyNo = 0
	card.sessionKey = sessionKey
	card.lastSelectedApplication = 0x00AE16

	card.ChangeKey(0,newKey,oldKey)

def ChangeKeyTest_AES2():
	print 'ChangeKeyTest_AES2'
	"""
	*** ChangeKey(KeyNo= 0)
	* SessKey IV:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	* New Key:     10 18 20 28 30 38 40 48 50 58 60 68 70 78 80 88 (AES)
	* CRC Crypto:  0x62638574
	* Cryptogram:  10 18 20 28 30 38 40 48 50 58 60 68 70 78 80 88 10 74 85 63 62 00 00 00 00 00 00 00 00 00 00 00
	* CryptogrEnc: 29 45 E3 76 0E 60 F4 A4 04 6B B8 A5 05 B3 1C F5 59 A3 A2 E0 52 13 BC 82 94 2C A6 AB 5D BC EC F5
	Sending:  00 00 FF 25 DB <D4 40 01 C4 00 29 45 E3 76 0E 60 F4 A4 04 6B B8 A5 05 B3 1C F5 59 A3 A2 E0 52 13 BC 82 94 2C A6 AB 5D BC EC F5> 99 00
	Response: 00 00 FF 04 FC <D5 41 00 00> EA 00 AA AA AA AA AA AA AA AA
	"""

	reader = DummyReader()
	reader.connect()
	reader.addResponse(('', 0x91, 0x00))
	reader.addExpectedRequest(hexstr2bytelist('90 C4 00 00 21 00 29 45 E3 76 0E 60 F4 A4 04 6B B8 A5 05 B3 1C F5 59 A3 A2 E0 52 13 BC 82 94 2C A6 AB 5D BC EC F5 00'))
	card = Desfire(reader)

	oldKey = DESFireKey(hexstr2hex('00 10 20 30 40 50 60 70 80 90 A0 B0 B0 A0 90 80'), DESFireKeyType.DF_KEY_AES)
	newKey = DESFireKey(hexstr2hex('10 18 20 28 30 38 40 48 50 58 60 68 70 78 80 88'), DESFireKeyType.DF_KEY_AES)
	newKey.keyVersion = 0x10
	sessionKey = DESFireKey(hexstr2hex('C2 A1 E4 7B 27 10 47 12 FE 6D 00 A7 11 77 A1 9B'), DESFireKeyType.DF_KEY_AES)

	sessionKey.CiperInit()

	card.isAuthenticated = True
	card.lastAuthKeyNo = 0
	card.sessionKey = sessionKey
	card.lastSelectedApplication = 0x00AE16

	card.ChangeKey(0,newKey,oldKey)


def ChangeKeyTest_AES3():
	print 'ChangeKeyTest_AES3'
	"""
	*** ChangeKey(KeyNo= 1)
	* SessKey IV:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
	* New Key:     00 10 20 30 40 50 60 70 80 90 A0 B0 B0 A0 90 80 (AES)
	* Cur Key:     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (AES)
	* CRC Crypto:  0x84B47033
	* CRC New Key: 0x1979E3BF
	* Cryptogram:  00 10 20 30 40 50 60 70 80 90 A0 B0 B0 A0 90 80 10 33 70 B4 84 BF E3 79 19 00 00 00 00 00 00 00

	* CryptogrEnc: E7 EC CB 6B D1 CA 64 BC 16 1A 12 B1 C0 24 F7 14 30 33 74 08 C8 A8 7E AC AB 7A 1F F1 89 51 FC A3
	Sending:  00 00 FF 25 DB <D4 40 01 C4 01 E7 EC CB 6B D1 CA 64 BC 16 1A 12 B1 C0 24 F7 14 30 33 74 08 C8 A8 7E AC AB 7A 1F F1 89 51 FC A3> 59 00
	Response: 00 00 FF 0C F4 <D5 41 00 00 21 28 D3 CD 9C 9A CF FF> FD 00
	RX CMAC:  21 28 D3 CD 9C 9A CF FF F6 EB 95 46 AD F3 5E 17
	"""

	reader = DummyReader()
	reader.connect()
	reader.addResponse(('', 0x91, 0x00))
	reader.addExpectedRequest(hexstr2bytelist('90 C4 00 00 21 01 E7 EC CB 6B D1 CA 64 BC 16 1A 12 B1 C0 24 F7 14 30 33 74 08 C8 A8 7E AC AB 7A 1F F1 89 51 FC A3 00'))
	card = Desfire(reader)

	oldKey = DESFireKey(hexstr2hex('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'), DESFireKeyType.DF_KEY_AES)
	newKey = DESFireKey(hexstr2hex('00 10 20 30 40 50 60 70 80 90 A0 B0 B0 A0 90 80'), DESFireKeyType.DF_KEY_AES)
	newKey.keyVersion = 0x10
	sessionKey = DESFireKey(hexstr2hex('C2 A1 E4 7B D8 10 00 44 FE 6D 00 A7 4D 7A B1 7C'), DESFireKeyType.DF_KEY_AES)

	sessionKey.CiperInit()

	card.isAuthenticated = True
	card.lastAuthKeyNo = 0
	card.sessionKey = sessionKey
	card.lastSelectedApplication = 0x00AE16

	card.ChangeKey(1,newKey,oldKey)

if __name__ == '__main__':
	import sys
	import json
	import pprint
	import ctypes

	global logger

	logging.basicConfig(level=logging.DEBUG)
	logger = logging.getLogger(__name__)

	testCase = 'online'

	if testCase == 'offline':

		AuthTest_DES()
		AuthTest_2DES()
		AuthTest_3DES()
		AuthTest_AES()
		AuthTest_AES2()

		ChangeKeyTest_2K3DES()
		ChangeKeyTest_3K3DES()
		ChangeKeyTest_AES()
		ChangeKeyTest_AES2()
		ChangeKeyTest_AES3()

	elif testCase == 'online':

		try:

			reader = PCSCReader()
			reader.connect()
			card = Desfire(reader)

			card.SelectApplication(0x000000)
			card.GetKeyVersion(0)

			key = DESFireKey(hexstr2hex('00 00 00 00 00 00 00 00'), DESFireKeyType.DF_KEY_2K3DES)
			card.Authenticate(0, key)

			card.GetCardVersion()
			card.FormatCard()

			#appid, keysettings, keycount, type
			keysettings = [DESFireKeySettings.KS_ALLOW_CHANGE_MK, DESFireKeySettings.KS_LISTING_WITHOUT_MK,DESFireKeySettings.KS_CREATE_DELETE_WITHOUT_MK,DESFireKeySettings.KS_CONFIGURATION_CHANGEABLE]
			card.CreateApplication(0x00DE16,keysettings,2, DESFireKeyType.DF_KEY_2K3DES)
			card.CreateApplication(0x00DE24,keysettings,2, DESFireKeyType.DF_KEY_3K3DES)
			card.CreateApplication(0x00AE16,keysettings,2, DESFireKeyType.DF_KEY_AES)
			card.CreateApplication(0xAABBCC,keysettings,1, DESFireKeyType.DF_KEY_2K3DES)

			card.GetApplicationIDs()
			card.DeleteApplication(0xAABBCC)

			card.GetApplicationIDs()
			card.SelectApplication(0x00DE16)

			key = DESFireKey(hexstr2hex('00 00 00 00 00 00 00 00'), DESFireKeyType.DF_KEY_2K3DES)
			card.Authenticate(0, key)
			card.GetKeySettings()
			#card.ChangeKeySettings(keysettings)

			card.GetKeySettings()

			"""
			------------------------------------------------------------
			----------------------- 2K3DES -----------------------------
			------------------------------------------------------------
			"""
			logger.debug('----------------------- 2K3DES -----------------------------')

			card.SelectApplication(0x00DE16)
			key = DESFireKey(hexstr2hex('00 00 00 00 00 00 00 00'), DESFireKeyType.DF_KEY_2K3DES)
			card.Authenticate(0,key)
			key1 = DESFireKey(hexstr2hex('00 10 20 31 40 50 60 70 80 90 A0 B0 B0 A0 90 80'), DESFireKeyType.DF_KEY_2K3DES)
			card.ChangeKey(0, key1, key)
			card.Authenticate(0,key1)
			key2 = DESFireKey(hexstr2hex('10 18 20 29 30 38 40 48 50 58 60 68 70 78 80 88'), DESFireKeyType.DF_KEY_2K3DES)
			card.ChangeKey(0,key2, key1)
			card.Authenticate(0,key2)
			#card.GetKeyVersion(0)
			key3 = DESFireKey(hexstr2hex('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'), DESFireKeyType.DF_KEY_2K3DES)
			logger.debug('ChangeKey(0,key3, key2)')
			card.ChangeKey(0,key3, key2)
			logger.debug('Authenticate(0, key3)')
			card.Authenticate(0, key3)
			key4 = DESFireKey(hexstr2hex('00 10 20 31 40 50 60 70 80 90 A0 B0 B0 A0 90 80'), DESFireKeyType.DF_KEY_2K3DES)
			logger.debug('card.ChangeKey(1,key4, key3)')
			card.ChangeKey(1,key4, key3)
			key5 = DESFireKey(hexstr2hex('10 18 20 29 30 38 40 48 50 58 60 68 70 78 80 88'), DESFireKeyType.DF_KEY_2K3DES)
			logger.debug('card.ChangeKey(1,key5, key4)')
			card.ChangeKey(1,key5, key4)
			logger.debug('card.Authenticate(1,key5)')
			card.Authenticate(1,key5)


			"""
			------------------------------------------------------------
			----------------------- 3K3DES -----------------------------
			------------------------------------------------------------
			"""
			logger.debug('----------------------- 3K3DES -----------------------------')
			card.SelectApplication(0x00DE24)
			key6 = DESFireKey(hexstr2hex('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'), DESFireKeyType.DF_KEY_3K3DES)
			card.Authenticate(0,key6)
			key7 = DESFireKey(hexstr2hex('00 10 20 31 40 50 60 70 80 90 A0 B0 B0 A0 90 80 70 60 50 40 30 20 10 00'), DESFireKeyType.DF_KEY_3K3DES)
			card.ChangeKey(0,key7,key6)
			card.Authenticate(0, key7)
			key8 = DESFireKey(hexstr2hex('10 18 20 29 30 38 40 48 50 58 60 68 70 78 80 88 90 98 A0 A8 B0 B8 C0 C8'), DESFireKeyType.DF_KEY_3K3DES)
			card.ChangeKey(0, key8, key7)
			card.Authenticate(0,key8)
			card.GetKeyVersion(0)
			key9 = DESFireKey(hexstr2hex('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'), DESFireKeyType.DF_KEY_3K3DES)
			card.ChangeKey(0,key9,key8)
			card.Authenticate(0, key9)
			keyA = DESFireKey(hexstr2hex('00 10 20 31 40 50 60 70 80 90 A0 B0 B0 A0 90 80 70 60 50 40 30 20 10 00'), DESFireKeyType.DF_KEY_3K3DES)
			card.ChangeKey(1, keyA, key9)
			keyB = DESFireKey(hexstr2hex('10 18 20 29 30 38 40 48 50 58 60 68 70 78 80 88 90 98 A0 A8 B0 B8 C0 C8'), DESFireKeyType.DF_KEY_3K3DES)
			card.ChangeKey(1,keyB,keyA)
			card.Authenticate(1, keyB)

			"""
			---------------------------------------------------------
			----------------------- AES -----------------------------
			---------------------------------------------------------
			"""
			logger.debug('----------------------- AES -----------------------------')
			card.SelectApplication(0x00AE16)
			keyC = DESFireKey(hexstr2hex('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'), DESFireKeyType.DF_KEY_AES)
			card.Authenticate(0,keyC)
			keyD = DESFireKey(hexstr2hex('00 10 20 30 40 50 60 70 80 90 A0 B0 B0 A0 90 80'), DESFireKeyType.DF_KEY_AES)
			keyD.keyVersion = 0x10
			card.ChangeKey(0,keyD,keyC)
			card.Authenticate(0,keyD)
			keyE = DESFireKey(hexstr2hex('10 18 20 28 30 38 40 48 50 58 60 68 70 78 80 88'), DESFireKeyType.DF_KEY_AES)
			keyE.keyVersion = 0x10
			card.ChangeKey(0, keyE,keyD)
			card.Authenticate(0, keyE)
			card.GetKeyVersion(0)
			keyF = DESFireKey(hexstr2hex('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'), DESFireKeyType.DF_KEY_AES)
			card.ChangeKey(0,keyF,keyE)
			card.Authenticate(0, keyF)
			key10 = DESFireKey(hexstr2hex('00 10 20 30 40 50 60 70 80 90 A0 B0 B0 A0 90 80'), DESFireKeyType.DF_KEY_AES)
			key10.keyVersion = 0x10
			card.ChangeKey(1,key10,keyF)
			key11 = DESFireKey(hexstr2hex('10 18 20 28 30 38 40 48 50 58 60 68 70 78 80 88'), DESFireKeyType.DF_KEY_AES)
			key11.keyVersion = 0x10
			card.ChangeKey(1,key11,key10)
			card.Authenticate(1, key11)

			"""
			--------------------------------------------------------------
			--------------------------------------------------------------
			--------------------------------------------------------------
			

			card.CreateStdDataFile(ID= 5, Size= 80)
			card.GetFileIDs()
			card.GetFileSettings(ID= 5)
			card.WriteFileData(ID= 5, Offset= 0, Length= 80)
			card.ReadFileData(ID= 5, Offset= 0, Length= 80)
			card.DeleteFile(ID= 5)
			card.GetFileIDs()
			card.SelectApplication(0x000000)
			card.Authenticate(KeyNo= 0, Key= 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 (DES))
			"""
			card.FormatCard()

		except DesfireException as e:
			print '---- !!!! TEST FAILED !!!! -----'
			print 'Exception: ' + e.msg