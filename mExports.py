import os;
from .cHTTPClient import cHTTPClient;
from .cHTTPClientUsingProxyServer import cHTTPClientUsingProxyServer;
if os.name == "nt":
  from .cHTTPClientUsingAutomaticProxyServer import cHTTPClientUsingAutomaticProxyServer;
  
from . import mExceptions;
# Pass down
from mHTTPConnection import \
    cHTTPConnection, \
    cHTTPHeader, cHTTPHeaders, \
    cHTTPRequest, cHTTPResponse, \
    cURL, \
    fs0GetExtensionForMediaType, fsb0GetMediaTypeForExtension;

__all__ = [
  "cHTTPClient",
  "cHTTPClientUsingProxyServer",
  "mExceptions",
  # Pass down from mHTTPConnection
  "cHTTPConnection",
  "cHTTPHeader", "cHTTPHeaders", 
  "cHTTPRequest", "cHTTPResponse",
  "cURL",
  "fs0GetExtensionForMediaType", "fsb0GetMediaTypeForExtension",
];
if os.name == "nt":
  __all__.append("cHTTPClientUsingAutomaticProxyServer");
