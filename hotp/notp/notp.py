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
from optparse import OptionParser

import sha, hmac
import ConfigParser
import urllib, sys, os

# clipboard works only under Windows
try:
	import win32clipboard
except ImportError:
	pass

# configuration file name
CONFIGURATION_FILE = "notp.ini"
# HOTP URL
HOTP_SITE = "http://hotp.cs.huji.ac.il"
# NOTP version
VERSION = "1.0"

class Clipboard(object):
	def setText(self, text):
		"""Copies the given text to the clipboard"""
		win32clipboard.OpenClipboard()
		win32clipboard.EmptyClipboard()
		win32clipboard.SetClipboardText(text)
		win32clipboard.CloseClipboard()
	
	def isBroken(self):
		"""Checks if the clipboard is not working (if the clipboard module is not loaded)"""
		return not "win32clipboard" in sys.modules.keys()

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
			decryptedKey = self._decryptKey(self._padPinCode(self._config.getPinCode()), self._hexStringToString(self._config.getKey()))
			hashedKey = self._hashKeys(decryptedKey, self._hexStringToString(hex(self._config.getCounter())))
			otp = self._getFinalOTP(hashedKey, self._getOffset(hashedKey, int(self._config.getTruncationOffset())), int(self._config.getDigits()))

			self._config.setCounter(self._config.getCounter() + 1)

			yield otp

class Configuration(object):
	# HOTP jad file path
	_HOTP_JAD_PATH = "http://hotp.cs.huji.ac.il/tokens/"

	def __init__(self):
		"""Initializes the configuration, which is read from the configuration file"""
		self._config = ConfigParser.ConfigParser()
		self._config.read(CONFIGURATION_FILE)

	def getKey(self):
		"""Gets the OTP key"""
		return self._config.get("HOTP", "Key")
	
	def getCounter(self):
		"""Gets the counter"""
		return long(self._config.get("HOTP", "Counter"), 16)

	def getDigits(self):
		"""Gets the number of OTP digits"""
		return self._config.get("HOTP", "Digits")

	def getTruncationOffset(self):
		"""Gets the truncation offset"""
		return self._config.get("HOTP", "TruncationOffset")

	def getPinCode(self):
		"""Gets the PIN code"""
		return self._config.get("HOTP", "Pincode")

	def setPinCode(self, value):
		"""Sets the PIN code to a given value"""
		self._config.set("HOTP", "Pincode", value)

		self._saveConfiguration()
	
	def setCounter(self, value):
		"""Sets the counter to a given value"""
		self._config.set("HOTP", "Counter", hex(value))

		self._saveConfiguration()
	
	def _saveConfiguration(self):
		"""Saves the configuration to a file"""
		configFile = file(CONFIGURATION_FILE, "wb")
		self._config.write(configFile)
		configFile.close()
	
	def exists(self):
		"""Checks if the configuration file exists"""
		return os.path.isfile(CONFIGURATION_FILE)
	
	def fetchConfiguration(self, id):
		"""Fetches configuration from JAD file, located in the HOTP server"""
		jadContents = urllib.urlopen("%s%d.jad" % (self._HOTP_JAD_PATH, id)).read()

		if not self._config.has_section("HOTP"):
			self._config.add_section("HOTP")

		for line in jadContents.split("\n"):
			try:
				(parameter, value) = line.split(": ")
			except ValueError:
				continue

			if parameter == "HOTP-Key":
				self._config.set("HOTP", "Key", value)
			elif parameter == "HOTP-Counter":
				self._config.set("HOTP", "Counter", value)
			elif parameter == "HOTP-Digits":
				self._config.set("HOTP", "Digits", value)
			elif parameter == "HOTP-Truncation-Offset":
				self._config.set("HOTP", "TruncationOffset", value)
			elif parameter == "MIDlet-Install-Notify":
				# emulate installation
				urllib.urlopen(value)

		if not self._config.has_option("HOTP", "TruncationOffset"):
			self._config.set("HOTP", "TruncationOffset", -1)
		
		self._saveConfiguration()

class NOTP(object):
	def run(self):
		"""Main NOTP entry point"""
		os.chdir(os.path.dirname(sys.argv[0]))

		self._config = Configuration()
		self._clipboard = Clipboard()

		usage = "usage: %prog [option]"
		parser = OptionParser(usage = usage, version="%%prog %s" % VERSION)

		if not self._clipboard.isBroken():
			parser.add_option("-c", "--clipboard", default=True, action="store_true", dest="clipboard",
							  help="generate an OTP to the clipboard (default)")
			parser.add_option("-p", "--print", action="store_true", dest="printOTP",
				  help="print the OTP to stdout")
		else:
			parser.add_option("-p", "--print", default=True, action="store_true", dest="printOTP",
					  help="print the OTP to stdout (default)z")

		parser.add_option("-i", "--install", action="store_true", dest="install",
						  help="install NOTP")
		parser.add_option("-a", "--advance", action="store", type="int", dest="advance",
						  help="advance the OTP x steps")
		parser.add_option("-r", "--regress", action="store", type="int", dest="regress",
						  help="regress the OTP x steps")
		
		(options, args) = parser.parse_args()

		if options.advance and options.regress:
		    parser.error("options -a and -r are mutually exclusive")
		
		elif options.install or not self._config.exists():
			self._install()
		elif options.advance:
			self._config.setCounter(self._config.getCounter() + options.advance)
		elif options.regress:
			self._config.setCounter(self._config.getCounter() - options.regress)
		elif options.printOTP:
			print self._getOTP()
		elif options.clipboard:
			self._generateToClipboard()
	
	def _getOTP(self):
		"""Retrieves the next OTP"""
		try:
			otpGenerator = OTPGenerator(self._config).getOTP()
			return otpGenerator.next()
		except ConfigParser.NoSectionError:
			print "Configuration file not found, go to %s and register." % HOTP_SITE

	def _generateToClipboard(self):
		"""Generates an OTP and copies it to the clipboard"""
		self._clipboard.setText(self._getOTP())
	
	def _install(self):
		"""Installs NOTP"""
		print "1. Surf to %s and register." % HOTP_SITE
		print "2. You'll receive an sms with a URL, ending with an ID (should be 4-5 digits)"
		sys.stdout.write("3. Enter the number you received here: ")

		jadID = sys.stdin.readline()

		config = Configuration()
		try :
			config.fetchConfiguration(int(jadID))
		except Exception, e:
			print "An error occured while trying to fetch configuration information: %s", e
			sys.exit()
		
		sys.stdout.write("4. Enter your PIN code here: ")

		config.setPinCode(sys.stdin.readline())

		print "5. We're done! You can always edit the configuration file (%s). Enjoy!" % CONFIGURATION_FILE

if __name__ == "__main__":
	NOTP().run()