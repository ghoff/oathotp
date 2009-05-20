'''
$Id$

Cryptography handling and processing module.

This module is in the public domain and was released on sourceforge:
http://sourceforge.net/projects/pycrypto patch 1466857

2005-10-03 Ids van der Molen <ids at idsvandermolen dot com>: Initial version
License: this python module is public domain.

This module provides some pycrypto support functions, like encryption/signing
schemes and PEM parsing/serialization (using PKCS1 ASN.1 format, which should
someday be replaced with OpenSSL compatible PKCS8 format).
Public key algorithm is RSA, default key length is 2048 bits. Maximum number of
encryptable or signable bytes can be determined with the size method. This is 
normally 256 bytes.
The public/private key classes use PKCS1 v1.5 encryption and signing schemes
(signing with SHA-1). This should be replaced with more save PKCS1 v2.1 schemes
(EME-OEAP and EMA-PSS).

Because public key algorithms are much slower than symmetric
ciphers (at least a factor 1000), generate a random key with the RandomPool, 
encrypt plaintext using a cipher and the random key. After this you can transmit
the ciphertext and use the Public key algorithm to transmit the random key and
optionally the initialization vector (iv).

Most ciphers available have several feedback modes (like CBC - Cipher Block 
Chaining, or CFB - Cipher FeedBack), which are more secure than the ECB - 
Electronic Code Book mode. However, to start the feedback mechanism, these 
feedback modes require initialization vectors (IVs) with a size equal to the 
cipher blocksize.

Example RSA Public/Private keypair usage (reusing random byte generator):
>>> import crypto
>>> pubkey, privkey = crypto.makeKeyPair()
>>> plaintext = crypto.pool.get_bytes(32)
>>> signature = privkey.sign(plaintext)
>>> assert pubkey.verify(plaintext, signature), 'invalid signature'
>>> ciphertext = pubkey.encrypt(plaintext)
>>> decryptedtext = privkey.decrypt(ciphertext)
>>> assert decryptedtext == plaintext, 'encrypt/decrypt failed'
>>> # serialize
>>> s = pubkey.serialize()
>>> # serialized form to key
>>> pubkey2 = crypto.makePublicKeyFrom(s)
>>> # serialize
>>> s = privkey.serialize()
>>> # serialized form to key
>>> privkey2 = crypto.makePrivateKeyFrom(s)
>>> # encode key into a PEM message
>>> pem = crypto.makePEMFromKey(pubkey)
>>> # decode PEM message into a key
>>> pubkey3 = crypto.makeKeyFromPEM(pem)

Example cipher usage:
>>> import crypto
>>> import Crypto.Cipher.AES as AES
>>> # we want AES-256-CBC
>>> key = crypto.pool.get_bytes(32)
>>> iv  = crypto.pool.get_bytes(AES.block_size)
>>> cipher = AES.new(key, AES.MODE_CBC, iv)
>>> plaintext = crypto.appendPadding(AES.block_size, plaintext)
>>> ciphertext = cipher.encrypt(plaintext)
>>> # reverse, needs cipher with newly set iv:
>>> cipher = AES.new(key, AES.MODE_CBC, iv)
>>> decryptedtext = cipher.decrypt(ciphertext)
>>> decryptedtext = crypto.removePadding(AES.block_size, decryptedtext)
>>> assert plaintext == decryptedtext, 'Oops: encrypt/decrypt failed'

Future enhancements: implement BOOL,OBJECTIDENTIFIER,OCTETSTRING ASN.1
                     implement pkcs#1 v2.1 EME-OAEP, EMSA-PSS, MGF1
                     implement pkcs#8 (PEM) key storage
Future fixes: Warning for RandomPool: if entropy < 0, the 
              entropy in the random pool should be increased by add_event to 
              prevent random generator attacks.
              Handle all possible exceptions from pyrypto modules.
Sources: http://www.amk.ca/python/code/crypto
         http://en.wikipedia.org/wiki/Abstract_syntax_notation
         http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
         http://www.columbia.edu/~ariel/ssleay/layman.html
'''

# import standard modules
import os
import re
import base64
import array
import sha

# import external modules
#from Crypto.Cipher import DES3, AES
import Crypto.PublicKey.RSA
from Crypto.Util.randpool import RandomPool
import Crypto.Util.number

#CIPHERS = {'DES-EDE3-CBC': {'factory': DES3.new, 'keysize': 24, 'mode': DES3.MODE_CBC, 'blocksize': DES3.block_size, 'needsIV': True},
#           'AES-128-CBC': {'factory': AES.new, 'keysize': 16, 'mode': AES.MODE_CBC, 'blocksize': AES.block_size, 'needsIV': True},
#           'AES-192-CBC': {'factory': AES.new, 'keysize': 24, 'mode': AES.MODE_CBC, 'blocksize': AES.block_size, 'needsIV': True},
#           'AES-256-CBC': {'factory': AES.new, 'keysize': 32, 'mode': AES.MODE_CBC, 'blocksize': AES.block_size, 'needsIV': True}
#          }

#DEFAULTCIPHER = 'AES-256-CBC'
DEFAULTBITS   = 2048

# ASN.1 tagnumbers
BOOL=0x01
INTEGER=0x02
BITSTRING=0x03
OCTETSTRING=0x04
NULL=0x05
OBJECTIDENTIFIER=0x06
SEQUENCE=0x10
SET=0x11

# PEM stuff
TOKENS = {'begin' : '-----BEGIN ', 'eol' : '-----', 'end' : '-----END '}
BEGINRE = r'^%(begin)s(?P<tag>[\S\s]*?\S)%(eol)s$\n' % TOKENS
BODYRE = r'^([\S\s]*?)$\n'
ENDRE = r'^%(end)s(?P=tag)%(eol)s$' % TOKENS
PEMRE = re.compile(BEGINRE + BODYRE + ENDRE, re.MULTILINE)
RSAPRIVATE = 'RSA PRIVATE KEY'
RSAPUBLIC = 'RSA PUBLIC KEY'

# default random pool:
pool = RandomPool()

# for PKCS1_V1_5 signing: 
SHA1DER = '\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14'
SHA1DERLEN = len(SHA1DER) + 0x14

#
# ============================================================================
#
class Error(Exception):
  'Base error exception'
  pass

#
# ============================================================================
#
def i2osp(x, xLen=None):
  'Integer to octetstring primitive.'
  s = Crypto.Util.number.long_to_bytes(x)
  if xLen is None:
    return s
  if len(s) > xLen:
    raise Error('integer too large')
  padding = '\x00' * (xLen - len(s))
  return padding + s

#
# ============================================================================
#
def os2ip(s):
  'Octetstring to integer primitive.'
  return Crypto.Util.number.bytes_to_long(s)

#
# ============================================================================
#
def nrPadBytes(blocksize, size):
  'Return number of required pad bytes for block of size.'
  if not (0 < blocksize < 255):
    raise Error('blocksize must be between 0 and 255')
  return blocksize - (size % blocksize)

#
# ============================================================================
#
def appendPadding(blocksize, s):
  '''Append rfc 1423 padding to string.

  RFC 1423 algorithm adds 1 up to blocksize padding bytes to string s. Each 
  padding byte contains the number of padding bytes.
  '''
  n = nrPadBytes(blocksize, len(s))
  return s + (chr(n) * n)

#
# ============================================================================
#
def removePadding(blocksize, s):
  'Remove rfc 1423 padding from string.'
  n = ord(s[-1]) # last byte contains number of padding bytes
  if n > blocksize or n > len(s):
    raise Error('invalid padding')
  return s[:-n]

#
# ============================================================================
#
def _emsa_pkcs1_v1_5_encode(M, emLen):
  H = sha.new(M).digest()
  T = SHA1DER + H
  if emLen < (SHA1DERLEN + 11):
    raise Error('intended encoded message length too short (%s)' % emLen)
  ps = '\xff' * (emLen - SHA1DERLEN - 3)
  if len(ps) < 8:
    raise Error('ps length too short')
  return '\x00\x01' + ps + '\x00' + T

#
# ============================================================================
#
class PublicKey:
  def __init__(self, inst):
    'Initialize public key with instance.'
    self._inst = inst
    self._k = Crypto.Util.number.size(inst.n)/8
    self._pkcs1 = None
    self._maxLen = self._k - 11

  def size(self):
    'Return maximum number of bytes that can be encrypted.'
    return self._k

  def encrypt(self, plaintext):
    'Encrypt plaintext and return ciphertext.'
    l = len(plaintext)
    if l > self._maxLen:
      raise Error('plaintext too long (%s bytes) for encryption (%s bytes max)' % (l, self._maxLen))
    em = self._eme_pkcs1_v1_5_encode(plaintext)
    m = os2ip(em)
    # second argument K is not used in RSA. Only first field in returned tuple is in use with RSA
    c = self._inst.encrypt(m, '')[0]
    return i2osp(c, self._k)

  def verify(self, plaintext, signature):
    'Verify signature with public key.'
    if len(signature) != self._k:
      raise Error('invalid signature')
    em = _emsa_pkcs1_v1_5_encode(plaintext, self._k)
    # second argument K is not used in RSA. Only first field in returned tuple is in use with RSA
    return self._inst.verify(em, (os2ip(signature),))

  def _eme_pkcs1_v1_5_encode(self, M):
    # k = size of n in octets (PublicKey.size)
    padlength = self._k - len(M) - 3
    if padlength < 8:
      raise Error('length of padding too short (%s < 8)' % (padlength))
    padding = array.array('B', pool.get_bytes(padlength))
    for i in xrange(padlength):
      if padding[i] == 0:
        padding[i] = self._getNonZeroByte()
    return '\x00\x02' + padding.tostring() + '\x00' + M

  def _getNonZeroByte(self):
    while True:
      b = pool.get_bytes(1)
      if ord(b) != 0:
        return ord(b)

  def serialize(self):
    'Return PKCS1 string representation.'
    # RSAPublicKey ::= SEQUENCE {
    #    modulus INTEGER, -- n
    #    publicExponent INTEGER -- e
    # }
    if not self._pkcs1:
      self._pkcs1 = DEREncoder([[self._inst.n, self._inst.e]]).encode()
    return self._pkcs1.tostring()

  def __str__(self):
    return self.serialize()

#
# ============================================================================
#
class PrivateKey:
  def __init__(self, inst):
    'Initialize private key with instance.'
    self._inst = inst
    self._k = Crypto.Util.number.size(inst.n)/8
    self._pkcs1 = None

  def size(self):
    'Return maximum number of bytes that can be signed.'
    return self._k

  def sign(self, plaintext):
    'Sign plaintext with private key.'
    em = _emsa_pkcs1_v1_5_encode(plaintext, self._k)
    # second argument K is not used in RSA. Only first field in returned tuple is in use with RSA
    s = i2osp(self._inst.sign(em, '')[0], self._k)
    return s
    
  def decrypt(self, ciphertext):
    'Decrypt ciphertext with private key.'
    l = len(ciphertext)
    if l != self._k:
      raise Error('ciphertext length (%s bytes) must be %s bytes' % (l, self._k))
    c = os2ip(ciphertext)
    em = i2osp(self._inst.decrypt(c), self._k)
    return self._eme_pkcs1_v1_5_decode(em)

  def _eme_pkcs1_v1_5_decode(self, em):
    if em[0:2] != '\x00\x02':
      raise Error('invalid padding (not starting with \x00\x02)')
    i = em[1:].find('\x00')
    if i == -1:
      raise Error('invalid padding (no \x00 found)')
    if  i <= 8:
      raise Error('invalid padding (ps length < 8)')
    return em[i+2:]

  def publicKey(self):
    'Return corresponding PublicKey.'
    return PublicKey(self._inst.publickey())

  def serialize(self):
    'Return PKCS1 string representation.'
    # RSAPrivateKey ::= SEQUENCE {
    #    version Version,
    #    modulus INTEGER, -- n
    #    publicExponent INTEGER, -- e
    #    privateExponent INTEGER, -- d
    #    prime1 INTEGER, -- p
    #    prime2 INTEGER, -- q
    #    exponent1 INTEGER, -- d mod (p-1)
    #    exponent2 INTEGER, -- d mod (q-1)
    #    coefficient INTEGER, -- (inverse of q) mod p
    #    otherPrimeInfos OtherPrimeInfos OPTIONAL
    # }
    #
    # Version ::= INTEGER { two-prime(0), multi(1) }
    # (CONSTRAINED BY {-- version must be multi if otherPrimeInfos present --})
    #
    # OtherPrimeInfos ::= SEQUENCE SIZE(1..MAX) OF OtherPrimeInfo
    # OtherPrimeInfo ::= SEQUENCE {
    # prime INTEGER, -- ri
    # exponent INTEGER, -- di
    # coefficient INTEGER -- ti
    # }

    if not self._pkcs1:
      self._pkcs1 = DEREncoder([[0, self._inst.n, self._inst.e, self._inst.d, 
                                 self._inst.p, self._inst.q, 
                                 self._inst.d % (self._inst.p - 1),
                                 self._inst.d % (self._inst.q -1),
                                 self._inst.u]]).encode()
    return self._pkcs1.tostring()

  def __str__(self):
    return self.serialize()

#
# ============================================================================
#
def makeKeyPair(bits=DEFAULTBITS, randfunc=None):
  'Create a new Public/Private keypair.'
  if randfunc is None:
    randfunc = pool.get_bytes
  try:
    obj = Crypto.PublicKey.RSA.generate(bits, randfunc)
  except Crypto.PublicKey.RSA.error, e:
    raise Error('makeKeyPair failed (%s)' % e)
  priv = PrivateKey(obj)
  pub  = PublicKey(obj.publickey())
  return pub, priv

#
# ============================================================================
#
def makeKeyFromPEM(pem):
  'Create PublicKey or PrivateKey from PEM message string.'
  codec = PEM()
  try:
    tag, data = codec.decode(pem)[0]
    if tag == RSAPUBLIC:
      return makePublicKeyFrom(data)
    if tag == RSAPRIVATE:
      return makePrivateKeyFrom(data)
  except IndexError:
    raise Error('invalid PEM message')

  raise Error('expected %s or %s tag in pem message, got %s' % (RSAPUBLIC, RSAPRIVATE, tag))

#
# ============================================================================
#
def makePEMFromKey(key):
  'Make a PEM string from Public/Private key object.'
  codec = PEM()
  if isinstance(key, PublicKey):
    return codec.encode(RSAPUBLIC, key.serialize())
  if isinstance(key, PrivateKey):
    return codec.encode(RSAPRIVATE, key.serialize())
  raise Error('expected PublicKey or PrivateKey instance')

#
# ============================================================================
#
def makePublicKeyFrom(s):
  'Create PublicKey from PKCS1 ASN.1 string.'
  try:
    n, e = BERDecoder(array.array('B', s)).decode()[0]
  except IndexError:
    raise Error('invalid public key')
  return PublicKey(Crypto.PublicKey.RSA.construct([n,e]))

#
# ============================================================================
#
def makePrivateKeyFrom(s):
  'Create PrivateKey from PKCS1 ASN.1 string.'
  try:
    privdata = BERDecoder(array.array('B', s)).decode()[0]
    version, n, e, d, p, q, ex1, ex2, u = privdata[:9]
    if version != 0:
      raise Error('expected RSA Private key version 0, got %s' % version)
  except IndexError:
    raise Error('invalid private key')
  return PrivateKey(Crypto.PublicKey.RSA.construct([n,e,d,p,q,u]))
    
#
# ============================================================================
#
class PEM:
  def decode(self, s):
    'Return list of decoded PEM message strings (tag and data string).'
    pems = PEMRE.findall(s)
    return [(tag, base64.decodestring(data)) for tag, data in pems]

  def encode(self, tag, data):
    'Encode tag and data string to PEM message string.'
    out = ['%s%s%s\n' % (TOKENS['begin'], tag, TOKENS['eol'])]
    out.extend(self._rewrap(base64.encodestring(data)))
    out.append('\n%s%s%s\n' % (TOKENS['end'], tag, TOKENS['eol']))
    return ''.join(out)
  
  def _rewrap(self, s):
    're-wrap to 64-char lines as required by PEM rfc 1421.'
    s = s.replace('\n','')
    return '\n'.join([s[i : i+64] for i in xrange(0, len(s), 64)])

#
# ============================================================================
#
class BERDecoder:
  def __init__(self, bytes):
    'Initialize with byte array.'
    self.bytes = bytes
    self.index = 0
    self.length = len(self.bytes)

  def __iter__(self):
    'Return iterator.'
    self.index = 0
    return self

  def next(self):
    'Return next item.'
    if self.index >= self.length:
      raise StopIteration
    return self._decodeNext()

  def _decodeNext(self):
    'Decode next item in stream.'
    #Get type, length and value
    constructed, tagnumber = self._decodeID()
    length = self._decodeLength()
    value = self._getBytes(length)

    if tagnumber == INTEGER and not constructed:
      return self._bytesToLong(value)

    if tagnumber == SEQUENCE and constructed:
      return [n for n in BERDecoder(value)]

    t='primitive'
    if constructed:
      t = 'constructed'
    raise Error('%s type with tag 0x%x not implemented' % (t, tagnumber))

  def decode(self):
    'Return a sequence of decoded items.'
    return [n for n in self]

  def _decodeID(self):
    'Decode identifier bytes.'
    # Get first identifier octet
    i = self._getBytes(1)[0]
    # bits 8,7 define class
    # 00 - Universal
    # 01 - Application
    # 10 - Context-specific
    # 11 - Private
    # bit 6 set -> constructed, otherwise primitive
    # bits 5,4,3,2,1 define tag number
    cl = (i & 0xC0) >> 5
    if cl != 0:
      raise Error('class of tag 0x%x not implemented' % cl)
    constructed = False
    if i & 0x20:
      constructed = True
    tagnum = i & 0x1F
    if tagnum == 0x1F:
      raise Error('multiple identifier octets / tagnumbers > 0x1F not implemented')
    return constructed, tagnum
    
  def _decodeLength(self):
    'Decode length.'
    firstLength = self._getBytes(1)[0]
    # if bit 8 set -> long form
    if firstLength & 0x80:
      # long form
      lengthLength = firstLength & 0x7F
      return self._bytesToLong(self._getBytes(lengthLength))
    # short form
    return firstLength

  def _bytesToLong(self, bytes):
    'Convert bytes array to long.'
    return os2ip(bytes.tostring())

  def _getBytes(self, nr):
    'Get nr bytes from stream.'
    if self.index + nr > self.length:
      raise Error('decode error: request %s bytes with %s left' % (nr, self.length - self.index))
    bytes = self.bytes[self.index:self.index+nr]
    self.index += nr
    return bytes

#
# ============================================================================
#
class DEREncoder:
  def __init__(self, seq):
    'Initialize with sequence of objects.'
    self.seq = seq
    self.index = 0
    self.length = len(seq)

  def __iter__(self):
    'Return iterator.'
    self.index = 0
    return self

  def next(self):
    'Return next item.'
    if self.index >= self.length:
      raise StopIteration
    return self._encodeNext()

  def _encodeNext(self):
    'Encode next item in sequence of objects.'
    obj = self._getObjects(1)[0]
    if type(obj) == type(0L) or type(obj) == type(0):
      tagnumber = INTEGER
      constructed = False
      value = self._longToBytes(obj)
    elif type(obj) == type([]) or type(obj) == type((1,)):
      tagnumber = SEQUENCE
      constructed = True
      value = array.array('B')
      for n in obj:
        value.extend(DEREncoder([n]).encode())
    else:
      raise Error('encoding of %s type objects not implemented' % type(obj))

    identifier = self._encodeID(constructed, tagnumber)
    length = self._encodeLength(len(value))
    return identifier + length + value

  def encode(self):
    'Return array of bytes with encoded objects.'
    out = array.array('B')
    for n in self:
      out.extend(n)
    return out

  def _encodeID(self, constructed, tagnumber):
    'Encode constructed, tagnumber into identifier bytes.'
    # bits 8,7 define class
    # 00 - Universal
    # 01 - Application
    # 10 - Context-specific
    # 11 - Private
    # bit 6 set -> constructed, otherwise primitive
    # bits 5,4,3,2,1 define tag number
    # no other classes but Universal implemented
    # multiple identifier octets if tagnumber > 0x1F not implemented
    i = 0 # assume Universal class, primitive, tagnumber 0
    if constructed:
      i |= 0x20 # constructed, not primitive
    i |= (tagnumber & 0x1F)
    return array.array('B',[i])

  def _encodeLength(self, length):
    'Encode length in bytes array.'
    if length > 127:
      # long form
      bytes = self._longToBytes(length)
      lengthLength = len(bytes)
      firstLength = array.array('B', [0x80 | lengthLength])
      return firstLength + bytes
    # short form
    return array.array('B', [0x7F & length])

  def _longToBytes(self, l):
    'Convert long l to bytes array.'
    return array.array('B', i2osp(l))

  def _getObjects(self, nr):
    'Get next nr objects from sequence.'
    if self.index + nr > self.length:
      raise Error('encode error: request %s objects with %s left' % (nr, self.length - self.index))
    objs = self.seq[self.index:self.index+nr]
    self.index += nr
    return objs

