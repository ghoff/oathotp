#    Copyright (C) 2008 Yaron Inger, http://ingeration.blogspot.com
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#    or download it from http://www.gnu.org/licenses/gpl.txt

from rijndael import rijndael

import sha, hmac
import urllib, sys, os

# NOTP version
VERSION = "1.0"

class OTPGenerator(object):
	# used to pad the PIN code
	_PADDING_STRING = "blablablabla"

	def __init__(self, config):
		"""Initializes a new OTPGenerator, by using configuration parameters"""
		self._config = config

	def _padPinCode(self, pinCode):
		"""Pads the given pin code with the padding string"""
		return (str(pinCode) + self._PADDING_STRING)[:16]

	def _hexStringToString(self, hexString):
		"""Converts the given hex string to a characters string"""
		strippedString = hexString.lstrip("0x").rstrip("L")
		outputString = ""

		for i in xrange(0, len(strippedString), 2):
			outputString = "".join((outputString, chr(int(strippedString[i:i+2], 16))))

		return outputString

	def _stringToBytesArray(self, text):
		"""Converts the given string to a bytes array"""
		byteArray = []

		for char in text:
			byteArray.append(ord(char))
		
		return byteArray

	def _decryptKey(self, key, buffer):
		"""Decrypts the given buffer using Rijndael encryption algorithm (AES)"""
		encryptor = rijndael(key, block_size = 16)

		# decrypt both blocks
		return "".join((encryptor.decrypt(buffer[:16]), encryptor.decrypt(buffer[16:])))

	def _hashKeys(self, initKey, updateKey):
		"""Returns an SHA-1 HMAC hash of the key"""
		hMAC = hmac.new(initKey, digestmod=sha)
		hMAC.update(updateKey)

		return [ord(char) for char in hMAC.digest()]

	def _getOffset(self, hashResult, truncationOffset):
		"""Retrieves the offset to calculate the OTP from"""
		if truncationOffset < 0:
			return hashResult[-1] & 0xF
		else:
			return truncationOffset

	def _getFinalOTP(self, hashResult, startingOffset, otpDigits):
		"""Retrieves the final OTP, calculated from the hash"""
		fullKey = (hashResult[startingOffset] & 0x7F) << 24 |\
			(hashResult[startingOffset + 1] & 0xFF) << 16 |\
			(hashResult[startingOffset + 2] & 0xFF) << 8 |\
			hashResult[startingOffset + 3] & 0xFF
		
		finalKey = str(fullKey)
		if len(finalKey) > otpDigits:
			finalKey = finalKey[len(finalKey) - otpDigits:]
		
		return finalKey
	
	def getOTP(self):
		"""Returns a genarator object for creating OTP's"""
		while True:
			if 1:
				decryptedKey = self._decryptKey(
				  self._padPinCode(self._config['pincode']), self._hexStringToString(self._config['key'])
				  )
			else:
				decryptedKey = self._config['key']
			hashedKey = self._hashKeys(decryptedKey, 
				self._hexStringToString(hex(self._config['counter'])))
			otp = self._getFinalOTP(hashedKey, 
				self._getOffset(hashedKey, int(self._config['truncationoffset'])), 
				int(self._config['digits']))
			yield otp

	
class NOTP(object):
	def run(self):
		"""Main NOTP entry point"""
		_config = {}
		_config['pincode'] = '123456'
		_config['key'] = '1234567890123456789012345678901212345678901234567890123456789012'
		#_config['key'] = ''
		_config['counter'] = 17
		_config['truncationoffset'] = 0
		_config['digits'] = 6
		otpGenerator = OTPGenerator(_config).getOTP()
		print otpGenerator.next()


if __name__ == "__main__":
	NOTP().run()
