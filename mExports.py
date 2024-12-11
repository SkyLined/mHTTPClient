import os;
from .cHTTPClient import cHTTPClient;
from .cHTTPClientUsingProxyServer import cHTTPClientUsingProxyServer;
if os.name == "nt":
  from .cHTTPClientUsingAutomaticProxyServer import cHTTPClientUsingAutomaticProxyServer;
  
from .mExceptions import (
  cHTTPClientException,
  cHTTPClientFailedToConnectToServerThroughProxyException,
);

__all__ = [
  "cHTTPClient",
  "cHTTPClientException",
  "cHTTPClientFailedToConnectToServerThroughProxyException",
  "cHTTPClientUsingProxyServer",
];
if os.name == "nt":
  __all__.append("cHTTPClientUsingAutomaticProxyServer");
