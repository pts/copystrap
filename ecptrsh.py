#! /usr/bin/python
# by pts@fazekas.hu at Thu May 24 13:57:43 CEST 2018

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


def main(argv):
  data = 'Hello, 3World!\nThe answer is 43.\n'
  print [data]
  token = upload_to_transfer_sh(data, 'd')
  print [token]
  # token = 'oDDHz'
  data2 = download_from_transfer_sh(token, 'd', expected_size=len(data))
  print [data2]
  assert data == data2


if __name__ == '__main__':
  sys.exit(main(sys.argv))
