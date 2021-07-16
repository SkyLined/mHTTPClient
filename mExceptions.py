# Passdown from mHTTPConnection (and mHTTPProtocol by extension)
from mHTTPConnection.mExceptions import *;

class cHTTPFailedToConnectToProxyException(cHTTPException):
  pass; # The proxy server did not respond to our CONNECT request with a 200 OK.

