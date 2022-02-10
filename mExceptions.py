# Passdown from mHTTPConnection (and mHTTPProtocol by extension)
from mHTTPConnection.mExceptions import *;
from mHTTPConnection.mExceptions import acExceptions as acHTTPConnectionExceptions;

class cHTTPClientFailedToConnectToServerThroughProxyException(cHTTPException):
  pass; # The proxy server did not respond to our CONNECT request with a 200 OK.

acExceptions = (
  acHTTPConnectionExceptions +
  [
    cHTTPClientFailedToConnectToServerThroughProxyException,
  ]
);
