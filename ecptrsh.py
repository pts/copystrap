#! /usr/bin/python
# by pts@fazekas.hu at Thu May 24 14:48:52 CEST 2018

"""copystrap: Copy encrypted data between 2 computers using transfer.sh"""

import base64
import hashlib
import os
import re
import socket
import sys
import httplib

# ---

# Fix for Python 2.6 on Ubuntu 10.04, and also Python 2.7.9 (or later 2.7.x)
# with incorrect root certificates.
# https://ptspts.blogspot.com/2016/11/how-to-fix-python-ssl-errors-when.html
import ssl as __ssl
__ssl.wrap_socket = __import__('functools').partial(
    __ssl.wrap_socket, ssl_version=__ssl.PROTOCOL_TLSv1)
if getattr(__ssl, '_create_unverified_context', None):
  __ssl._create_default_https_context = __ssl._create_unverified_context
del __ssl

# ---

URL_RE = re.compile(r'([a-z0-9]+)://([^/:@?#]+)(?::(\d+))?')


def send_http_request(url, data=None, put_data=None, timeout=None):
  """Return a httplib.HTTPResponse object with attributes
  .status, .reason, .getheaders(), .getheader(...), .read()."""
  match = URL_RE.match(url)
  if not match:
    raise ValueError('Bad URL: %s' % url)
  schema = match.group(1)
  if schema not in ('http', 'https'):
    raise ValueError('Unknown schema: %s' % schema)
  host = match.group(2)
  if match.group(3):
    port = int(match.group(3))
  else:
    port = (80, 443)[schema == 'https']
  path = url[match.end():] or '/'
  ipaddr = socket.gethostbyname(host)  # Force IPv4. Needed by Mega.
  hc_cls = (httplib.HTTPConnection, httplib.HTTPSConnection)[schema == 'https']
  # TODO(pts): Cleanup: Call hc.close() eventually.
  if sys.version_info < (2, 6):  # Python 2.5 doesn't support timeout.
    hc = hc_cls(ipaddr, port)
  else:
    hc = hc_cls(ipaddr, port, timeout=timeout)
  headers = {'host': host}
  if put_data is not None:
    headers.setdefault('content-type', 'application/octet-stream')
    if data is not None:
      raise ValueError('Both data= and put_data= specified.')
    hc.request('PUT', path, put_data, headers)
  elif data is not None:
    headers.setdefault('content-type', 'application/x-www-form-urlencoded')
    hc.request('POST', path, data, headers)
  else:
    hc.request('GET', path, None, headers)
  return hc.getresponse()  # HTTPResponse.


# ---


# https://github.com/dutchcoders/transfer.sh/blob/master/server/codec.go
TR_TOKEN_RE_STR = r'[0-9a-zA-Z]{2,10}'

TR_TOKEN_RE = re.compile(TR_TOKEN_RE_STR + r'\Z')

TR_DL_URL_RE = re.compile(
    r'https://([^/:@?#]+)/(' + TR_TOKEN_RE_STR + ')/(?s)(.*)\Z')


def upload_to_transfer_sh(data, filename='t', host='transfer.sh'):
  # TODO(pts): Escape filename.
  # TODO(pts): Escape host?
  hr = send_http_request(
      'https://%s/%s' % (host, filename), put_data=data)
  try:
    if hr.status != 200:
      raise ValueError('HTTP request failed: %s %s' % (hr.status, hr.reason))
    if hr.getheader('content-type') != 'text/plain':
      raise ValueError(
          'Unexpected response content-type: %s' % hr.getheader('content-type'))
    content_length = int(hr.getheader('content-length') or 0)
    if not 12 <= content_length - len(host) - len(filename) <= 20:
      raise ValueError('Unexpected response content-length: %s' %
                       content_length)
    body = hr.read()
    if len(body) != content_length:
      raise ValueError('Inconsistent response body and content-length.')
    # https://github.com/dutchcoders/transfer.sh/blob/master/server/codec.go
    match = TR_DL_URL_RE.match(body)
    if not match:
      raise ValueError('Invalid transfer.sh download URL: %s' % body)
    if match.group(1) != host or match.group(3) != filename:
      raise ValueError('Bad values in transfer.sh download URL: %s' % body)
    return match.group(2)  # token.
  finally:
    hr.close()


def download_from_transfer_sh(
    token, filename='t', host='transfer.sh', expected_size=None):
  """Returns the full file data downloaded."""
  if not TR_TOKEN_RE.match(token):
    raise ValueError('Invalid token: %s', token)
  url = 'https://%s/%s/%s' % (host, token, filename)
  hr = send_http_request(url)
  try:
    if hr.status != 200:
      raise ValueError('HTTP request failed: %s %s' % (hr.status, hr.reason))
    content_length = int(hr.getheader('content-length') or 0)
    if expected_size is not None and expected_size != content_length:
      raise ValueError('Bad data size: expected=%d got=%d' %
                       (expected_size, content_length))
    cd = hr.getheader('content-disposition') or ''
    if cd != 'attachment; filename="%s"' % filename:
      raise ValueError('Unexpected response content-disposition: %s' % cd)
    # Ignore hr.getheader('content-type'). Can also be empty ('').
    body = hr.read()
    if len(body) != content_length:
      raise ValueError('Inconsistent response body and content-length.')
  finally:
    hr.close()
  return body


def use_fake_transfer_sh(_files={}):
  """Use an in-memory fake transfer.sh storage. Useful for testing."""

  global upload_to_transfer_sh
  def upload_to_transfer_sh(data, filename='t', host='transfer.sh'):
    data = str(data)
    while 1:
      token = str(len(_files))
      key = '%s/%s/%s' % (host, token, filename)
      _files.setdefault(key, data)
      if _files[key] == data:
        break
      # Do it again if another thread was faster.
    return token

  global download_from_transfer_sh
  def download_from_transfer_sh(
      token, filename='t', host='transfer.sh', expected_size=None):
    key = '%s/%s/%s' % (host, token, filename)
    data = _files.get(key)
    if data is None:
      raise KeyError('Missing token key: %s' % key)
    return data


# ---


def curve25519_scalarmult(n, p=None):
  """Curve25519 key exchange (curve25519-donna).
  
  Implementation based on
  https://github.com/pts/py_ssh_keygen_ed25519/blob/master/curve25519_compact.py
  """
  # n is a group element string, p is a string representing an integer. Both
  # are 32 bytes.
  if len(n) != 32:
    raise ValueError('Invalid Curve25519 n.')
  if p is None:
    u = 9
  else:
    if len(p) != 32:
      raise ValueError('Invalid Curve25519 p.')
    u = int(p[::-1].encode('hex'), 16)
  k = (int(n[::-1].encode('hex'), 16) & ~(1 << 255 | 7)) | 1 << 254
  ql, x1, x2, z2, x3, z3, do_swap = (1 << 255) - 19, u, 1, 0, u, 1, 0
  for t in xrange(254, -1, -1):
    kt = (k >> t) & 1
    if do_swap ^ kt:
      x2, x3, z2, z3 = x3, x2, z3, z2
    do_swap = kt
    a, b = (x2 + z2) % ql, (x2 - z2) % ql
    aa, bb = (a * a) % ql, (b * b) % ql
    c, d = (x3 + z3) % ql, (x3 - z3) % ql
    da, cb = d * a % ql, c * b % ql
    d1, d2 = da + cb, da - cb
    x3, z3 = d1 * d1 % ql, x1 * d2 * d2 % ql
    x2, e = aa * bb % ql, (aa - bb) % ql
    z2 = e * (aa + 121665 * e) % ql
  if do_swap:
    x2, x3, z2, z3 = x3, x2, z3, z2
  return ('%064x' % ((x2 * pow(z2, ql - 2, ql)) % ql)).decode('hex')[::-1]


# --- Digest.


def digest32(data):
  """Returns a 32-byte message digest."""
  return hashlib.sha256(data).digest()


# --- RC4 symmetric cipher implementation.
#
# !! Replace it with more secure crypto.

def rc4_encrypt(data, key):
  """Returns the ciphertext.

  Implementation based on
  https://github.com/jbremer/rc4/blob/master/rc4/__init__.py
  """
  if not isinstance(data, str):
    raise TypeError
  if not isinstance(key, str):
    raise TypeError
  if not key:
    raise ValueError('Key is empty.')

  s, j, lk = list(xrange(256)), 0, len(key)
  for i in xrange(256):
    j = (j + s[i] + ord(key[i % lk])) & 255
    s[i], s[j] = s[j], s[i]

  def yield_bytes():
    i = j = 0
    for c in data:
      i = (i + 1) & 255
      j = (j + s[i]) & 255
      s[i], s[j] = s[j], s[i]
      yield chr(ord(c) ^ (s[(s[i] + s[j]) & 255]))

  return ''.join(yield_bytes())


assert rc4_encrypt('Hello World', 'rc4') == '*,\xb606]\x9e2\xf0\x8a\xa5'
assert rc4_encrypt('*,\xb606]\x9e2\xf0\x8a\xa5', 'rc4') == 'Hello World'


def encrypt(data, key):
  # RC4-drop[3072], see https://en.wikipedia.org/wiki/RC4
  return rc4_encrypt(os.urandom(3072) + data, key)


def decrypt(data, key):
  data = rc4_encrypt(data, key)
  if len(data) < 3072:
    raise ValueError('Ciphertext too short.')
  return data[3072:]


# ---

SEND_DATA_RE = re.compile('SPK=([a-zA-Z0-9+/]{43}=)\n\n')


def main(argv):
  use_fake_transfer_sh()  # !! Make it optional.

  # Done by the receiver.
  recv_private = os.urandom(32)
  recv_public =  curve25519_scalarmult(recv_private)
  recv_token = upload_to_transfer_sh(recv_public, 'r')
  print [recv_token]  # Send recv_token to the sender.

  # Done by the sender.
  data = 'No news today.'
  recv_public2 = download_from_transfer_sh(recv_token, 'r', expected_size=32)
  assert recv_public == recv_public2
  send_private = os.urandom(32)
  send_public =  curve25519_scalarmult(send_private)
  key = curve25519_scalarmult(send_private, recv_public2)
  data_encrypted = encrypt(digest32(data) + data, key)
  send_data = 'SPK=%s\n\n%s' % (base64.b64encode(send_public), data_encrypted)
  send_token = upload_to_transfer_sh(send_data, 's')
  print [send_token]  # Send send_token to the receiver.
  
  # Done by the receiver.
  send_data2 = download_from_transfer_sh(send_token, 's')
  match = SEND_DATA_RE.match(send_data2)
  if not match:
    raise ValueError('Invalid send_data.')
  send_public2 = base64.b64decode(match.group(1))
  data_encrypted2 = send_data2[match.end():]
  key2 = curve25519_scalarmult(recv_private, send_public2)
  data2 = decrypt(data_encrypted2, key2)
  if len(data2) < 32:
    raise ValueError('Encrypted data too short.')
  data3 = data2[32:]
  if digest32(data3) != data2[:32]:
    raise ValueError('Corrupt data: digest does not match.')
  print [key, data]
  print [key2, data3]


if __name__ == '__main__':
  sys.exit(main(sys.argv))
