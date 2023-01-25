import os, re;

assert os.name == "nt", \
  "This module is only implemented for Windows";

from mWindowsSDK.mWinHTTP import \
    DWORD, \
    LPCWSTR, \
    NULL, \
    oWinHTTPDLL, \
    WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, \
    WINHTTP_ACCESS_TYPE_NAMED_PROXY, \
    WINHTTP_ACCESS_TYPE_NO_PROXY, \
    WINHTTP_AUTO_DETECT_TYPE_DHCP, \
    WINHTTP_AUTO_DETECT_TYPE_DNS_A, \
    WINHTTP_AUTOPROXY_ALLOW_AUTOCONFIG, \
    WINHTTP_AUTOPROXY_ALLOW_CM, \
    WINHTTP_AUTOPROXY_ALLOW_STATIC, \
    WINHTTP_AUTOPROXY_AUTO_DETECT, \
    WINHTTP_AUTOPROXY_OPTIONS, \
    WINHTTP_AUTOPROXY_SORT_RESULTS, \
    WINHTTP_NO_PROXY_BYPASS, \
    WINHTTP_NO_PROXY_NAME, \
    WINHTTP_PROXY_INFO;
try: # mDebugOutput use is Optional
  from mDebugOutput import ShowDebugOutput, fShowDebugOutput;
except ModuleNotFoundError as oException:
  if oException.args[0] != "No module named 'mDebugOutput'":
    raise;
  ShowDebugOutput = lambda fx: fx; # NOP
  fShowDebugOutput = lambda x, s0 = None: x; # NOP

from mMultiThreading import cLock, cWithCallbacks;
from mHTTPProtocol import cURL;
from mNotProvided import \
    fbIsProvided, \
    fxzGetFirstProvidedValueIfAny, \
    zNotProvided;
try: # SSL support is optional.
  from mSSL import cCertificateStore as c0CertificateStore;
except:
  c0CertificateStore = None; # No SSL support

from .cHTTPClient import cHTTPClient;
from .cHTTPClientUsingProxyServer import cHTTPClientUsingProxyServer;
from .iHTTPClient import iHTTPClient;
from .mExceptions import *;

# To turn access to data store in multiple variables into a single transaction, we will create locks.
# These locks should only ever be locked for a short time; if it is locked for too long, it is considered a "deadlock"
# bug, where "too long" is defined by the following value:
gnDeadlockTimeoutInSeconds = 1; # We're not doing anything time consuming, so this should suffice.

class cHTTPClientUsingAutomaticProxyServer(iHTTPClient, cWithCallbacks):
  u0zDefaultMaxNumberOfConnectionsToServerWithoutProxy = 10;
  u0zDefaultMaxNumberOfConnectionsToProxy = 10; # zNotProvided => use value from 
  n0zDefaultConnectTimeoutInSeconds = 10;
  n0zDefaultSecureTimeoutInSeconds = 5;
  n0zDefaultTransactionTimeoutInSeconds = 10;
  n0zDefaultConnectToProxyTimeoutInSeconds = 10;
  n0zDefaultSecureConnectionToProxyTimeoutInSeconds = 5;
  n0zDefaultSecureConnectionToServerTimeoutInSeconds = 5;
  
  @ShowDebugOutput
  def __init__(oSelf,
    o0zCertificateStore = zNotProvided, 
    bVerifyCertificatesForProxy = True, bCheckProxyHostname = True,
    u0zMaxNumberOfConnectionsToServerWithoutProxy = zNotProvided,
    u0zMaxNumberOfConnectionsToProxy = zNotProvided,
    n0zConnectTimeoutInSeconds = zNotProvided, n0zSecureTimeoutInSeconds = zNotProvided, n0zTransactionTimeoutInSeconds = zNotProvided,
    n0zConnectToProxyTimeoutInSeconds = zNotProvided, n0zSecureConnectionToProxyTimeoutInSeconds = zNotProvided,
    n0zSecureConnectionToServerTimeoutInSeconds = zNotProvided,
    bVerifyCertificates = True, bCheckHostname = True,
  ):
    oSelf.__hInternet = oWinHTTPDLL.WinHttpOpen(
      LPCWSTR("User-Agent"), # LPCWSTR pszAgentW
      WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, # DWORD dwAccessType
      WINHTTP_NO_PROXY_NAME, # LPCWSTR pszProxyW
      WINHTTP_NO_PROXY_BYPASS, # LPCWSTR pszProxyBypassW
      NULL, # DWORD dwFlags
    );
    if oSelf.__hInternet == NULL:
      from mWindowsSDK.mKernel32 import oKernel32DLL;
      from mWindowsSDK import fsGetWin32ErrorCodeDescription;
      uLastError = oKernel32DLL.GetLastError().fuGetValue();
      raise AssertionError("Cannot initialize WinHTTP: error 0x%08X (%s)." % (uLastError, fsGetWin32ErrorCodeDescription(uLastError)));
    # This code will instantiate other classes to make requests. A single certificate store instance is used by all
    # these instances.
    oSelf.__o0CertificateStore = (
      o0zCertificateStore if fbIsProvided(o0zCertificateStore) else
      c0CertificateStore() if c0CertificateStore else
      None
    );
    oSelf.__bVerifyCertificatesForProxy = bVerifyCertificatesForProxy;
    oSelf.__bCheckProxyHostname = bCheckProxyHostname;
    #
    oSelf.__u0zMaxNumberOfConnectionsToServerWithoutProxy = fxzGetFirstProvidedValueIfAny(u0zMaxNumberOfConnectionsToServerWithoutProxy, oSelf.u0zDefaultMaxNumberOfConnectionsToServerWithoutProxy);
    #
    oSelf.__u0zMaxNumberOfConnectionsToProxy = fxzGetFirstProvidedValueIfAny(u0zMaxNumberOfConnectionsToProxy, oSelf.u0zDefaultMaxNumberOfConnectionsToProxy);
    # Timeouts can be provided through class default, instance defaults, or method call arguments.
    oSelf.__n0zConnectTimeoutInSeconds = fxzGetFirstProvidedValueIfAny(n0zConnectTimeoutInSeconds, oSelf.n0zDefaultConnectTimeoutInSeconds);
    oSelf.__n0zSecureTimeoutInSeconds = fxzGetFirstProvidedValueIfAny(n0zSecureTimeoutInSeconds, oSelf.n0zDefaultSecureTimeoutInSeconds);
    oSelf.__n0zTransactionTimeoutInSeconds = fxzGetFirstProvidedValueIfAny(n0zTransactionTimeoutInSeconds, oSelf.n0zDefaultTransactionTimeoutInSeconds);
    #
    oSelf.__n0zConnectToProxyTimeoutInSeconds = fxzGetFirstProvidedValueIfAny(n0zConnectToProxyTimeoutInSeconds, oSelf.n0zDefaultConnectToProxyTimeoutInSeconds);
    oSelf.__n0zSecureConnectionToProxyTimeoutInSeconds = fxzGetFirstProvidedValueIfAny(n0zSecureConnectionToProxyTimeoutInSeconds, oSelf.n0zDefaultSecureConnectionToProxyTimeoutInSeconds);
    #
    oSelf.__n0zSecureConnectionToServerTimeoutInSeconds = fxzGetFirstProvidedValueIfAny(n0zSecureConnectionToServerTimeoutInSeconds, oSelf.n0zDefaultSecureConnectionToServerTimeoutInSeconds);
    #
    oSelf.__bVerifyCertificates = bVerifyCertificates;
    oSelf.__bCheckHostname = bCheckHostname;
    #############################
    oSelf.__oPropertyAccessTransactionLock = cLock(
      "%s.__oPropertyAccessTransactionLock" % oSelf.__class__.__name__,
      n0DeadlockTimeoutInSeconds = gnDeadlockTimeoutInSeconds
    );
    oSelf.__oDirectHTTPClient = None;
    oSelf.__doHTTPClientUsingProxyServer_by_sbLowerProxyServerURL = {};
    
    oSelf.__bStopping = False;
    oSelf.__oTerminatedLock = cLock("%s.__oTerminatedLock" % oSelf.__class__.__name__, bLocked = True);
    
    oSelf.fAddEvents(
      "proxy selected",
      "client created", "client terminated",
      # direct client
      "server hostname or ip address invalid",
      
      "resolving server hostname", "resolving server hostname failed", "server hostname resolved to ip address",
      
      "connecting to server ip address", "connecting to server ip address failed",
      "connecting to server failed", "connection to server created", "connection to server terminated",
      # proxy clients
      "proxy hostname or ip address invalid",
      "resolving proxy hostname", "resolving proxy hostname failed", "proxy hostname resolved to ip address",
      "connecting to proxy ip address", "connecting to proxy ip address failed",
      "connecting to proxy failed", "connection to proxy created", "connection to proxy terminated",
      
      "secure connection to server through proxy created",
      
      "bytes written", "bytes read",
      "request sent", "response received", "request sent and response received",
      
      "terminated",
    );
  
  @property
  def bStopping(oSelf):
    return oSelf.__bStopping;
  
  @ShowDebugOutput
  def fStop(oSelf):
    oSelf.__oPropertyAccessTransactionLock.fAcquire();
    try:
      if oSelf.bTerminated:
        return fShowDebugOutput("Already terminated");
      if oSelf.__bStopping:
        return fShowDebugOutput("Already stopping");
      fShowDebugOutput("Stopping...");
      # Prevent any new cHTTPConnectionsToServerPool instances from being created.
      oSelf.__bStopping = True;
      oDirectHTTPClient = oSelf.__oDirectHTTPClient;
      aoHTTPClientsUsingProxyServer = list(oSelf.__doHTTPClientUsingProxyServer_by_sbLowerProxyServerURL.values());
    finally:
      oSelf.__oPropertyAccessTransactionLock.fRelease();
    if not oDirectHTTPClient:
      if len(aoHTTPClientsUsingProxyServer) == 0:
        # We stopped when there were no clients: we are terminated.
        fShowDebugOutput("Terminated.");
        oSelf.__oTerminatedLock.fRelease();
        oSelf.fFireEvent("terminated");
    else:
      oDirectHTTPClient.fStop();
    for oHTTPClientUsingProxyServer in aoHTTPClientsUsingProxyServer:
      oHTTPClientUsingProxyServer.fStop();
  
  @property
  def bTerminated(oSelf):
    return not oSelf.__oTerminatedLock.bLocked;
  
  @ShowDebugOutput
  def fTerminate(oSelf):
    oSelf.__oPropertyAccessTransactionLock.fAcquire();
    try:
      if oSelf.bTerminated:
        return fShowDebugOutput("Already terminated.");
      fShowDebugOutput("Terminating...");
      oSelf.__bStopping = True;
      oDirectHTTPClient = oSelf.__oDirectHTTPClient;
      aoHTTPClientsUsingProxyServer = list(oSelf.__doHTTPClientUsingProxyServer_by_sbLowerProxyServerURL.values());
    finally:
      oSelf.__oPropertyAccessTransactionLock.fRelease();
    if not oDirectHTTPClient:
      if len(aoHTTPClientsUsingProxyServer) == 0:
        # We terminated when there were no clients: we are terminated.
        fShowDebugOutput("Terminated.");
        oSelf.__oTerminatedLock.fRelease();
        oSelf.fFireEvent("terminated");
    else:
      oDirectHTTPClient.fTerminate();
    for oHTTPClientUsingProxyServer in aoHTTPClientsUsingProxyServer:
      oHTTPClientUsingProxyServer.fTerminate();
    return;
  
  @ShowDebugOutput
  def fWait(oSelf):
    return oSelf.__oTerminatedLock.fWait();
  @ShowDebugOutput
  def fbWait(oSelf, n0TimeoutInSeconds):
    return oSelf.__oTerminatedLock.fbWait(n0TimeoutInSeconds);
  
  @ShowDebugOutput
  def fo0GetProxyServerURLForURL(oSelf, oURL):
    dwAutoProxyFlags = DWORD(
      WINHTTP_AUTOPROXY_ALLOW_AUTOCONFIG
      | WINHTTP_AUTOPROXY_ALLOW_CM
      | WINHTTP_AUTOPROXY_ALLOW_STATIC
      | WINHTTP_AUTOPROXY_AUTO_DETECT
      | WINHTTP_AUTOPROXY_SORT_RESULTS
    );
    dwAutoDetectFlags = DWORD(
      WINHTTP_AUTO_DETECT_TYPE_DHCP
      | WINHTTP_AUTO_DETECT_TYPE_DNS_A
    );
    oWinHTTPAutoProxyOptions = WINHTTP_AUTOPROXY_OPTIONS(
      dwAutoProxyFlags, # DWORD   dwFlags;
      dwAutoDetectFlags, # DWORD   dwAutoDetectFlags;
      NULL, # LPCWSTR lpszAutoConfigUrl;
      NULL, # LPVOID  lpvReserved;
      NULL, # DWORD   dwReserved;
      True, # BOOL    fAutoLogonIfChallenged;
    );
    oWinHTTPProxyInfo = WINHTTP_PROXY_INFO();
    sURL = str(oURL);
    bSuccess = oWinHTTPDLL.WinHttpGetProxyForUrl(
      oSelf.__hInternet, # HINTERNET hSession
      LPCWSTR(sURL), # LPCWSTRlpcwszUrl
      oWinHTTPAutoProxyOptions.foCreatePointer(), # WINHTTP_AUTOPROXY_OPTIONS *pAutoProxyOptions,
      oWinHTTPProxyInfo.foCreatePointer(), # WINHTTP_PROXY_INFO *pProxyInfo
    );
    if not bSuccess:
      from mWindowsSDK.mKernel32 import oKernel32DLL;
      from mWindowsSDK import fsGetWin32ErrorCodeDescription;
      uLastError = oKernel32DLL.GetLastError().fuGetValue();
      raise AssertionError("Cannot call WinHttpGetProxyForUrl for URL %s: error 0x%08X (%s)." % (sURL, uLastError, fsGetWin32ErrorCodeDescription(uLastError)));
     
    if oWinHTTPProxyInfo.dwAccessType == WINHTTP_ACCESS_TYPE_NO_PROXY:
      return None;
    assert oWinHTTPProxyInfo.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY, \
        "Unexpected oWinHTTPProxyInfo.dwAccessType (0x%X)" % oWinHTTPProxyInfo.dwAccessType;
    assert not oWinHTTPProxyInfo.lpszProxy.fbIsNULLPointer(), \
        "Unexpected oWinHTTPProxyInfo.lpszProxy == NULL";
    assert oWinHTTPProxyInfo.lpszProxyBypass.fbIsNULLPointer(), \
        "Unexpected oWinHTTPProxyInfo.lpszProxyBypass == %s" % repr(oWinHTTPProxyInfo.lpszProxyBypass.fsGetString());
    sProxyInformation = str(oWinHTTPProxyInfo.lpszProxy.fsGetString());
#    print "-" * 80;
#    print repr(sProxyInformation);
#    print "-" * 80;
    # We get a list of proxy servers, separated by whitespace and/or semi-colons.
    # We will only use the first and discard the rest.
    oProxyInformationMatch = re.match(
      r"^"
      r"(?:" r"(\w+)=" r")?"    # optional "<scheme>="
      r"(?:" r"(\w+)://" r")?"  # optional "scheme://"
      r"([\w\-\.]+)"            # "<hostname>"
      r"(?:" r":(\d+)" r")?"    # optional ":<port>"
      r"(?:[\s;].*)?"           # optional (" " or ";") "<more proxy information>"
      r"$",
      sProxyInformation,
    );
    assert oProxyInformationMatch, \
        "Badly formed proxy information: %s" % repr(sProxyInformation);
    (s0Scheme1, s0Scheme2, sHostname, s0PortNumber) = oProxyInformationMatch.groups();
    oProxyURL = cURL(
      sProtocol = s0Scheme1 or s0Scheme2 or "http", #oURL.sbProtocol,
      sHostname = sHostname,
      u0PortNumber = int(s0PortNumber) if s0PortNumber else None,
    );
    return oProxyURL;
    
  @ShowDebugOutput
  def fo0GetResponseForRequestAndURL(oSelf, 
    oRequest, oURL,
    u0zMaxStatusLineSize = zNotProvided,
    u0zMaxHeaderNameSize = zNotProvided,
    u0zMaxHeaderValueSize = zNotProvided,
    u0zMaxNumberOfHeaders = zNotProvided,
    u0zMaxBodySize = zNotProvided,
    u0zMaxChunkSize = zNotProvided,
    u0zMaxNumberOfChunks = zNotProvided,
    u0MaxNumberOfChunksBeforeDisconnecting = None, # disconnect and return response once this many chunks are received.
  ):
    if oSelf.__bStopping:
      fShowDebugOutput("Stopping.");
      return None;
    o0HTTPClient = oSelf.__fo0GetHTTPClientForURL(oURL);
    if oSelf.__bStopping:
      fShowDebugOutput("Stopping.");
      return None;
    assert o0HTTPClient is not None, \
        "This is unexpected";
    oHTTPClient = o0HTTPClient;
    return oHTTPClient.fo0GetResponseForRequestAndURL(
      oRequest, oURL,
      u0zMaxStatusLineSize = u0zMaxStatusLineSize,
      u0zMaxHeaderNameSize = u0zMaxHeaderNameSize,
      u0zMaxHeaderValueSize = u0zMaxHeaderValueSize,
      u0zMaxNumberOfHeaders = u0zMaxNumberOfHeaders,
      u0zMaxBodySize = u0zMaxBodySize,
      u0zMaxChunkSize = u0zMaxChunkSize,
      u0zMaxNumberOfChunks = u0zMaxNumberOfChunks,
      u0MaxNumberOfChunksBeforeDisconnecting = u0MaxNumberOfChunksBeforeDisconnecting,
    );
  
  @ShowDebugOutput
  def fo0GetConnectionAndStartTransactionForURL(oSelf, oURL, bSecure = True):
    if oSelf.__bStopping:
      fShowDebugOutput("Stopping.");
      return None;
    o0HTTPClient = oSelf.__fo0GetHTTPClientForURL(oURL);
    if oSelf.__bStopping:
      fShowDebugOutput("Stopping.");
      return None;
    assert o0HTTPClient is not None, \
        "This is unexpected";
    oHTTPClient = o0HTTPClient;
    return oHTTPClient.fo0GetConnectionAndStartTransactionForURL(oURL, bSecure);
  
  @ShowDebugOutput
  def __fo0GetHTTPClientForURL(oSelf, oURL):
    if oSelf.__bStopping:
      fShowDebugOutput("Stopping.");
      return None;
    o0ProxyServerURL = oSelf.fo0GetProxyServerURLForURL(oURL);
    oSelf.fFireCallbacks(
      "proxy selected",
      oURL = oURL,
      o0ProxyServerURL = o0ProxyServerURL,
    );
    bNewClient = False;
    if o0ProxyServerURL is None:
      if oSelf.__oDirectHTTPClient is None:
        oClient = oSelf.__oDirectHTTPClient = cHTTPClient(
          o0zCertificateStore = oSelf.__o0CertificateStore,
          u0zMaxNumberOfConnectionsToServer = oSelf.__u0zMaxNumberOfConnectionsToServerWithoutProxy,
          n0zConnectTimeoutInSeconds = oSelf.__n0zConnectTimeoutInSeconds,
          n0zSecureTimeoutInSeconds = oSelf.__n0zSecureTimeoutInSeconds,
          n0zTransactionTimeoutInSeconds = oSelf.__n0zTransactionTimeoutInSeconds,
          bVerifyCertificates = oSelf.__bVerifyCertificates,
          bCheckHostname = oSelf.__bCheckHostname,
        );
        oClient.fAddCallbacks({
          "server hostname or ip address invalid": lambda oClient, sbHostnameOrIPAddress: oSelf.fFireCallbacks(
            "server hostname or ip address invalid",
            oClient = oClient,
            sbHostnameOrIPAddress = sbHostnameOrIPAddress,
          ),
          "resolving server hostname": lambda oClient, sbHostname: oSelf.fFireCallbacks(
            "resolving server hostname",
            oClient = oClient,
            sbHostname = sbHostname,
          ),
          "resolving server hostname failed": lambda oClient, sbHostname: oSelf.fFireCallbacks(
            "resolving server hostname failed",
            oClient = oClient,
            sbHostname = sbHostname,
          ),
          "server hostname resolved to ip address": lambda oClient, sbHostname, sIPAddress, sCanonicalName: oSelf.fFireCallbacks(
            "server hostname resolved to ip address",
            oClient = oClient,
            sbHostname = sbHostname,
            sIPAddress = sIPAddress,
            sCanonicalName = sCanonicalName,
          ),
          "connecting to server ip address": lambda oClient, sbHostnameOrIPAddress, sIPAddress, uPortNumber, sbzHostname: oSelf.fFireCallbacks(
            "connecting to server ip address",
            oClient = oClient,
            sbHostnameOrIPAddress = sbHostnameOrIPAddress,
            sIPAddress = sIPAddress,
            uPortNumber = uPortNumber,
            sbzHostname = sbzHostname,
          ),
          "connecting to server ip address failed": lambda oClient, oException, sbHostnameOrIPAddress, sIPAddress, uPortNumber, sbzHostname: oSelf.fFireCallbacks(
            "connecting to server ip address failed",
            oClient = oClient,
            oException = oException,
            sbHostnameOrIPAddress = sbHostnameOrIPAddress,
            sIPAddress = sIPAddress,
            uPortNumber = uPortNumber,
            sbzHostname = sbzHostname,
          ),
          "connecting to server failed": lambda oClient, sbHostnameOrIPAddress, uPortNumber, oException: oSelf.fFireCallbacks(
            "connecting to server failed",
            oClient = oClient,
            sbHostnameOrIPAddress = sbHostnameOrIPAddress,
            uPortNumber = uPortNumber,
            oException = oException,
          ),
          "connection to server created": lambda oClient, oConnection, sbHostnameOrIPAddress: oSelf.fFireCallbacks(
            "connection to server created",
            oClient = oClient,
            oConnection = oConnection,
            sbHostnameOrIPAddress = sbHostnameOrIPAddress,
          ),
          "connection to server terminated": lambda oClient, oConnection, sbHostnameOrIPAddress: oSelf.fFireCallbacks(
            "connection to server terminated",
            oClient = oClient,
            oConnection = oConnection,
            sbHostnameOrIPAddress = sbHostnameOrIPAddress,
          ),
          "terminated": oSelf.__fHandleTerminatedCallbackFromDirectHTTPClient,
        });
        bNewClient = True;
      else:
        oClient = oSelf.__oDirectHTTPClient;
    else:
      sLowerProxyServerURL = str(o0ProxyServerURL).lower();
      oClient = oSelf.__doHTTPClientUsingProxyServer_by_sbLowerProxyServerURL.get(sLowerProxyServerURL);
      if oClient is None:
        oClient = oSelf.__doHTTPClientUsingProxyServer_by_sbLowerProxyServerURL[sLowerProxyServerURL] = cHTTPClientUsingProxyServer(
          o0ProxyServerURL,
          bVerifyCertificatesForProxy = oSelf.__bVerifyCertificatesForProxy,
          bCheckProxyHostname = oSelf.__bCheckProxyHostname,
          o0zCertificateStore = oSelf.__o0CertificateStore,
          u0zMaxNumberOfConnectionsToProxy = oSelf.__u0zMaxNumberOfConnectionsToProxy,
          n0zConnectToProxyTimeoutInSeconds = oSelf.__n0zConnectToProxyTimeoutInSeconds,
          n0zSecureConnectionToProxyTimeoutInSeconds = oSelf.__n0zSecureConnectionToProxyTimeoutInSeconds,
          n0zSecureConnectionToServerTimeoutInSeconds = oSelf.__n0zSecureConnectionToServerTimeoutInSeconds,
          n0zTransactionTimeoutInSeconds = oSelf.__n0zTransactionTimeoutInSeconds,
          bVerifyCertificates = oSelf.__bVerifyCertificates,
          bCheckHostname = oSelf.__bCheckHostname,
        );
        oClient.fAddCallbacks({
          "proxy hostname or ip address invalid": lambda oClient, sbHostnameOrIPAddress: oSelf.fFireCallbacks(
            "proxy hostname or ip address invalid",
            oClient = oClient,
            sbHostnameOrIPAddress = sbHostnameOrIPAddress,
          ),
          "resolving proxy hostname": lambda oClient, sbHostname: oSelf.fFireCallbacks(
            "resolving proxy hostname",
            oClient = oClient,
            sbHostname = sbHostname,
          ),
          "resolving proxy hostname failed": lambda oClient, sbHostname: oSelf.fFireCallbacks(
            "resolving proxy hostname failed",
            oClient = oClient,
            sbHostname = sbHostname,
          ),
          "proxy hostname resolved to ip address": lambda oClient, sbHostname, sIPAddress, sCanonicalName: oSelf.fFireCallbacks(
            "proxy hostname resolved to ip address",
            oClient = oClient,
            sbHostname = sbHostname,
            sIPAddress = sIPAddress,
            sCanonicalName = sCanonicalName,
          ),
          "connecting to proxy ip address": lambda oClient, oProxyServerURL, sIPAddress, sbzHostname: oSelf.fFireCallbacks(
            "connecting to proxy ip address",
            oClient = oClient,
            oProxyServerURL = oProxyServerURL,
            sIPAddress = sIPAddress,
            sbzHostname = sbzHostname,
          ),
          "connecting to proxy ip address failed": lambda oClient, oException, oProxyServerURL, sIPAddress, sbzHostname: oSelf.fFireCallbacks(
            "connecting to proxy ip address failed",
            oClient = oClient,
            oException = oException,
            oProxyServerURL = oProxyServerURL,
            sIPAddress = sIPAddress,
            sbzHostname = sbzHostname,
          ),
          "connecting to proxy failed": lambda oClient, oConnection, oProxyServerURL: oSelf.fFireCallbacks(
            "connecting to proxy failed",
            oClient = oClient,
            oConnection = oConnection,
            oProxyServerURL = oProxyServerURL,
          ),
          "connection to proxy created": lambda oClient, oConnection, oProxyServerURL: oSelf.fFireCallbacks(
            "connection to proxy created",
            oClient = oClient,
            oConnection = oConnection,
            oProxyServerURL = oProxyServerURL,
          ),
          "secure connection to server through proxy created": lambda oClient, oConnection, oProxyServerURL, oServerURL: oSelf.fFireCallbacks(
            "secure connection to server through proxy created",
            oClient = oClient,
            oConnection = oConnection,
            oProxyServerURL = oProxyServerURL,
            oServerURL = oServerURL,
          ),
          "secure connection to server through proxy terminated": lambda oClient, oConnection, oProxyServerURL, oServerURL: oSelf.fFireCallbacks(
            "secure connection to server through proxy terminated",
            oClient = oClient,
            oConnection = oConnection,
            oProxyServerURL = oProxyServerURL,
            oServerURL = oServerURL,
          ),
          "connection to proxy terminated": lambda oClient, oConnection, oProxyServerURL: oSelf.fFireCallbacks(
            "connection to proxy terminated",
            oClient = oClient,
            oConnection = oConnection,
            oProxyServerURL = oProxyServerURL,
          ),
          "terminated": oSelf.__fHandleTerminatedCallbackFromHTTPClientUsingProxyServer,
        });
        bNewClient = True;
    
    if bNewClient:
      oClient.fAddCallbacks({
        "bytes written": lambda oClient, oConnection, sbBytesWritten: oSelf.fFireCallbacks(
          "bytes written",
          oClient = oClient,
          o0ProxyServerURL = o0ProxyServerURL,
          oConnection = oConnection,
          sbBytesWritten = sbBytesWritten,
        ),
        "bytes read": lambda oClient, oConnection, sbBytesRead: oSelf.fFireCallbacks(
          "bytes read",
          oClient = oClient,
          o0ProxyServerURL = o0ProxyServerURL,
          oConnection = oConnection,
          sbBytesRead = sbBytesRead,
        ),
        "request sent": lambda oClient, oConnection, oRequest: oSelf.fFireCallbacks(
          "request sent",
          oClient = oClient,
          o0ProxyServerURL = o0ProxyServerURL,
          oConnection = oConnection,
          oRequest = oRequest,
        ),
        "response received": lambda oClient, oConnection, oResponse: oSelf.fFireCallbacks(
          "response received",
          oClient = oClient,
          o0ProxyServerURL = o0ProxyServerURL,
          oConnection = oConnection,
          oResponse = oResponse,
        ),
        "request sent and response received": lambda oClient, oConnection, oRequest, oResponse: oSelf.fFireCallbacks(
          "request sent and response received",
          oClient = oClient,
          o0ProxyServerURL = o0ProxyServerURL,
          oConnection = oConnection,
          oRequest = oRequest,
          oResponse = oResponse,
        ),
      });
      oSelf.fFireCallbacks(
        "client created",
        oClient = oClient,
        o0ProxyServerURL = o0ProxyServerURL,
      );
    return oClient;
    
  def __fHandleTerminatedCallbackFromDirectHTTPClient(oSelf, oClient):
    oSelf.fFireCallbacks(
      "client terminated",
      oClient = oClient,
      o0ProxyServerURL = None,
    );
    oSelf.__oPropertyAccessTransactionLock.fAcquire();
    try:
      oSelf.__oDirectHTTPClient = None;
      # Return if we are not stopping or if there are other connections open:
      if not oSelf.__bStopping or oSelf.__doHTTPClientUsingProxyServer_by_sbLowerProxyServerURL:
        return;
    finally:
      oSelf.__oPropertyAccessTransactionLock.fRelease();
    # We are stopping and the last connection just terminated: we are terminated.
    fShowDebugOutput("Terminated.");
    oSelf.__oTerminatedLock.fRelease();
    oSelf.fFireCallbacks("terminated");
  
  def __fHandleTerminatedCallbackFromHTTPClientUsingProxyServer(oSelf, oClient):
    oSelf.fFireCallbacks(
      "client terminated",
      oClient = oClient,
      o0ProxyServerURL = oClient.oProxyServerURL,
    );
    sLowerProxyServerURL = str(oClient.oProxyServerURL).lower();
    oSelf.__oPropertyAccessTransactionLock.fAcquire();
    try:
      assert oClient is oSelf.__doHTTPClientUsingProxyServer_by_sbLowerProxyServerURL[sLowerProxyServerURL], \
          "Client for proxy server URL %s is %s instead of %s" % (
            sLowerProxyServerURL,
            oSelf.__doHTTPClientUsingProxyServer_by_sbLowerProxyServerURL[sLowerProxyServerURL],
            oClient
          );
      del oSelf.__doHTTPClientUsingProxyServer_by_sbLowerProxyServerURL[sLowerProxyServerURL];
      # Return if we are not stopping or if there are other connections open:
      if not oSelf.__bStopping or oSelf.__oDirectHTTPClient or oSelf.__doHTTPClientUsingProxyServer_by_sbLowerProxyServerURL:
        return;
    finally:
      oSelf.__oPropertyAccessTransactionLock.fRelease();
    # We are stopping and the last connection just terminated: we are terminated.
    fShowDebugOutput("Terminated.");
    oSelf.__oTerminatedLock.fRelease();
    oSelf.fFireCallbacks("terminated");
  
  def fasGetDetails(oSelf):
    # This is done without a property lock, so race-conditions exist and it
    # approximates the real values.
    if oSelf.bTerminated:
      return ["terminated"];
    return [s for s in [
      "with%s direct client" % ("" if oSelf.__oDirectHTTPClient else "out"),
      "%s proxy clients" % (
        str(len(oSelf.__doHTTPClientUsingProxyServer_by_sbLowerProxyServerURL))
            if oSelf.__doHTTPClientUsingProxyServer_by_sbLowerProxyServerURL
        else "no"
      ),
      "stopping" if oSelf.__bStopping else None,
    ] if s];

for cException in acExceptions:
  setattr(cHTTPClientUsingAutomaticProxyServer, cException.__name__, cException);
