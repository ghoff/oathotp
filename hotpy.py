#    Copyright (C) 2009 Geoff Hoff, http://github.com/ghoff
#    Based on notp by
#    Copyright (C) 2008 Yaron Inger, http://ingeration.blogspot.com,
#    http://idsvandermolen.com/codefiles/crypto.py
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

import hmac, sys, os
import binascii, struct
from Crypto.Cipher import AES
import hashlib

class HOTP(object):

	def __init__(self, config):
		"""Initializes a new HOTP instance, by using configuration parameters
		For getOTP, config must include
		pincode = pin used to encrypt seed
		seed = encrypted seed record
		iv = initalization vector used to encrypt seed
		digits = number of digits of generated otp
		offset = otp offset, defaults to -1
		For cryptSeed, only pincode and seed are required"""
		self._config = config
		self._decryptedKey = None
		self._blocksize = 16
		if not self._config.has_key('offset'):
			self._config['offset'] = -1

	def _hashStr(self, code):
		hdata = hashlib.sha1(code)
		return hdata.digest()

	def _stripPadding(self, buffer):
		count = ord(buffer[-1])
		if count > self._blocksize or count >= len(buffer):
			raise Exception, "decryption failure"
		return buffer[:-count]

	def _addPadding(self, buffer):
		blocksize = self._blocksize
		pad = blocksize - (len(buffer) % blocksize)
		buffer = buffer + (pad * chr(pad))
		return buffer

	def _decryptKey(self, key, iv, buffer):
		cipher = AES.new(key[:16], AES.MODE_CBC, iv)
		clear_buffer = cipher.decrypt(buffer)
		clear_buffer = self._stripPadding(clear_buffer)
		return clear_buffer

	def _encryptKey(self, key, iv, buffer):
		cipher = AES.new(key[:16], AES.MODE_CBC, iv)
		buffer = self._addPadding(buffer)
		ebuffer = cipher.encrypt(buffer)
		return ebuffer

	def _HMACKeys(self, initKey, updateKey):
		"""Returns an SHA-1 HMAC hash of the key"""
		hMAC = hmac.new(initKey, updateKey, digestmod=hashlib.sha1)
		return hMAC.digest()

	def _getOffset(self, hashResult, truncationOffset):
		"""Retrieves the offset to calculate the OTP from"""
		if truncationOffset < 0:
			return ord(hashResult[-1]) & 0xF
		else:
			return truncationOffset

	def _getFinalOTP(self, hashResult, startingOffset, otpDigits):
		"""Retrieves the final OTP, calculated from the hash"""
		fullKey = (ord(hashResult[startingOffset]) & 0x7F) << 24 |\
			(ord(hashResult[startingOffset + 1]) & 0xFF) << 16 |\
			(ord(hashResult[startingOffset + 2]) & 0xFF) << 8 |\
			ord(hashResult[startingOffset + 3]) & 0xFF
		finalKey = str(fullKey)
		if len(finalKey) > otpDigits:
			finalKey = finalKey[-otpDigits:]
		return finalKey

	def _decrypt_key(self):
		if not self._config.has_key('iv'):
			raise Exception, "iv not set"
		self._decryptedKey = self._decryptKey(self._hashStr(self._config['pincode']), 
			binascii.a2b_hex(self._config['iv']),
			binascii.a2b_hex(self._config['seed']))

	def getOTP(self, counter):
		"""Returns a genarator object for creating OTP's"""
		# decrypt key if not already decrypted
		if not self._decryptedKey:
			self._decrypt_key()
		# counter must be 8 bytes big endian, pad to proper length
		counter = struct.pack('>q', counter)
		hashedKey = self._HMACKeys(self._decryptedKey, counter)
		offset = self._getOffset(hashedKey, self._config['offset'])
		otp = self._getFinalOTP(hashedKey, offset, self._config['digits'])
		return otp

	def cryptSeed(self):
		iv = os.urandom(self._blocksize)
		eseed = self._encryptKey(self._hashStr(self._config['pincode']), 
			iv, binascii.a2b_hex(self._config['seed']))
		return binascii.b2a_hex(eseed), binascii.b2a_hex(iv)


def test():
	config = {}
	#_config['key'] = '3132333435363738393031323334353637383930'
	config['pincode'] = '7740'
	config['seed'] = '626ebf4c79386ccda44d6c39fb5a3f61e5154d18351ae757d3c51d8db4e5bb57'
	config['iv'] = 'a5e3fd9432eb48c36e53e93240056aed'
	config['digits'] = 6

	otp = HOTP(config)
	for i in range(0, 10):
		print otp.getOTP(i)


if __name__ == "__main__":
	test()

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
