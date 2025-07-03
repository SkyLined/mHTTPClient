import os;
from .cClient import cClient;
from .cClientUsingProxyServer import cClientUsingProxyServer;
if os.name == "nt":
  from .cClientUsingAutomaticProxyServer import cClientUsingAutomaticProxyServer;
  
from .mExceptions import (
  cClientException,
  cClientFailedToConnectToServerThroughProxyException,
);

__all__ = [
  "cClient",
  "cClientException",
  "cClientFailedToConnectToServerThroughProxyException",
  "cClientUsingProxyServer",
];
if os.name == "nt":
  __all__.append("cClientUsingAutomaticProxyServer");
