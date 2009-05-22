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

#from rijndael import rijndael

import sha, hmac, sys, os
import binascii

# NOTP version
VERSION = "1.0"

class OTPGenerator(object):

	def __init__(self, config):
		"""Initializes a new OTPGenerator, by using configuration parameters"""
		self._config = config

	def _hexStringToString(self, hexString):
		"""Converts the given hex string to a characters string"""
		strippedString = hexString.lstrip("0x").rstrip("L")

		# a2b_hex only works with even length strings
		if len(strippedString)%2:
			strippedString = '0' + strippedString 
		outputString = binascii.a2b_hex(strippedString)

		return outputString

	#def _decryptKey(self, key, buffer):
	#	"""Decrypts the given buffer using Rijndael encryption algorithm (AES)"""
	#	encryptor = rijndael(key, block_size = 16)
	#
	#	# decrypt both blocks
	#	return "".join((encryptor.decrypt(buffer[:16]), encryptor.decrypt(buffer[16:])))

	def _hashKeys(self, initKey, updateKey):
		"""Returns an SHA-1 HMAC hash of the key"""
		hMAC = hmac.new(initKey, updateKey, digestmod=sha)

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
			#decryptedKey = self._decryptKey(self._padPinCode(self._config['pincode']), 
			#	self._hexStringToString(self._config['key']))
			decryptedKey = self._hexStringToString(self._config['key'])

			counter = self._hexStringToString(hex(self._config['counter']))
			counter = '\0'*(8-len(counter))+counter
			hashedKey = self._hashKeys(decryptedKey,counter)
			#print "".join("%02x" % b for b in hashedKey)

			otp = self._getFinalOTP(hashedKey, self._getOffset(hashedKey, -1), 
				int(self._config['digits']))
			yield otp
			self._config['counter'] = self._config['counter'] + 1

	
class NOTP(object):
	def run(self):
		"""Main NOTP entry point"""
		_config = {}
		_config['pincode'] = '123456'
		_config['key'] = '3132333435363738393031323334353637383930'
		_config['counter'] = 0
		_config['digits'] = 6

		otpGenerator = OTPGenerator(_config).getOTP()
		for i in range(0, 10):
			print otpGenerator.next()


if __name__ == "__main__":
	NOTP().run()

""" RFC4226
Appendix D - HOTP Algorithm: Test Values


   The following test data uses the ASCII string
   "12345678901234567890" for the secret:

   Secret = 0x3132333435363738393031323334353637383930

   Table 1 details for each count, the intermediate HMAC value.

   Count    Hexadecimal HMAC-SHA-1(secret, count)
   0        cc93cf18508d94934c64b65d8ba7667fb7cde4b0
   1        75a48a19d4cbe100644e8ac1397eea747a2d33ab
   2        0bacb7fa082fef30782211938bc1c5e70416ff44
   3        66c28227d03a2d5529262ff016a1e6ef76557ece
   4        a904c900a64b35909874b33e61c5938a8e15ed1c
   5        a37e783d7b7233c083d4f62926c7a25f238d0316
   6        bc9cd28561042c83f219324d3c607256c03272ae
   7        a4fb960c0bc06e1eabb804e5b397cdc4b45596fa
   8        1b3c89f65e6c9e883012052823443f048b4332db
   9        1637409809a679dc698207310c8c7fc07290d9e5

   Table 2 details for each count the truncated values (both in
   hexadecimal and decimal) and then the HOTP value.

                     Truncated
   Count    Hexadecimal    Decimal        HOTP
   0        4c93cf18       1284755224     755224
   1        41397eea       1094287082     287082
   2         82fef30        137359152     359152
   3        66ef7655       1726969429     969429
   4        61c5938a       1640338314     338314
   5        33c083d4        868254676     254676
   6        7256c032       1918287922     287922
   7         4e5b397         82162583     162583
   8        2823443f        673399871     399871
   9        2679dc69        645520489     520489
"""
