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
    *,
    o0CookieStore = None,
    o0zCertificateStore = zNotProvided, 
    bVerifyCertificatesForProxy = True,
    bzCheckProxyHost = zNotProvided,
    u0zMaxNumberOfConnectionsToServerWithoutProxy = zNotProvided,
    u0zMaxNumberOfConnectionsToProxy = zNotProvided,
    n0zConnectTimeoutInSeconds = zNotProvided,
    n0zSecureTimeoutInSeconds = zNotProvided,
    n0zTransactionTimeoutInSeconds = zNotProvided,
    n0zConnectToProxyTimeoutInSeconds = zNotProvided,
    n0zSecureConnectionToProxyTimeoutInSeconds = zNotProvided,
    n0zSecureConnectionToServerTimeoutInSeconds = zNotProvided,
    nSendDelayPerByteInSeconds = 0,
    bVerifyCertificates = True,
    bzCheckHost = zNotProvided,
  ):
    super().__init__(
      o0CookieStore = o0CookieStore,
    );
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
    oSelf.__bzCheckProxyHost = bzCheckProxyHost;
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
    oSelf.__bzCheckHost = bzCheckHost;
    #############################
    oSelf.__oPropertyAccessTransactionLock = cLock(
      "%s.__oPropertyAccessTransactionLock" % oSelf.__class__.__name__,
      n0DeadlockTimeoutInSeconds = gnDeadlockTimeoutInSeconds
    );
    oSelf.__oDirectHTTPClient = None;
    oSelf.__doHTTPClientUsingProxyServer_by_sbLowerProxyServerURL = {};
    
    oSelf.__bStopping = False;
    oSelf.__oTerminatedLock = cLock("%s.__oTerminatedLock" % oSelf.__class__.__name__, bLocked = True);
    oSelf.nSendDelayPerByteInSeconds = 0;
    
    oSelf.fAddEvents(
      "selected proxy",
      "created client",
      "terminated client",
      
      # direct client
      "server host invalid",
      
      "resolving server hostname to ip address",
      "resolving server hostname to ip address failed",
      "resolved server hostname to ip address",
      
      "connecting to server",
      "connecting to server failed",
      "created connection to server",
      "terminated connection to server",
      
      "securing connection to server",
      "securing connection to server failed",
      "secured connection to server",
      
      "received out-of-band data from server",
      
      "sending request to server",
      "sending request to server failed",
      "sent request to server",
      
      "receiving response from server",
      "receiving response from server failed",
      "received response from server",
      
      # proxy clients
      "proxy host invalid",
      
      "resolving proxy hostname",
      "resolving proxy hostname failed",
      "resolved proxy hostname to ip address",
      
      "connecting to proxy",
      "connecting to proxy failed",
      "created connection to proxy",
      "terminated connection to proxy",
      
      "connecting to server through proxy",
      "connecting to server through proxy failed",
      "created connection to server through proxy",
      
      "securing connection to server through proxy",
      "securing connection to server through proxy failed",
      "secured connection to server through proxy",
      
      "received out-of-band data from proxy",
      
      "sending request to proxy",
      "sending request to proxy failed",
      "sent request to proxy",
      
      "receiving response from proxy",
      "receiving response from proxy failed",
      "received response from proxy",
      
      "read bytes",
      "wrote bytes", 
      
      "terminated",
    );
  
  @property
  def bStopping(oSelf):
    return oSelf.__bStopping;
  
  @property
  def bTerminated(oSelf):
    return not oSelf.__oTerminatedLock.bLocked;
  
  def fSetSendDelayPerByteInSeconds(oSelf, nSendDelayPerByteInSeconds):
    oSelf.nSendDelayPerByteInSeconds = nSendDelayPerByteInSeconds;
    oSelf.__oDirectHTTPClient.fSetSendDelayPerByteInSeconds(nSendDelayPerByteInSeconds);
    for oHTTPClient in oSelf.__doHTTPClientUsingProxyServer_by_sbLowerProxyServerURL.values():
      oHTTPClient.fSetSendDelayPerByteInSeconds(nSendDelayPerByteInSeconds);
  
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
      r"([\w\-\.]+)"            # "<host>"
      r"(?:" r":(\d+)" r")?"    # optional ":<port>"
      r"(?:[\s;].*)?"           # optional (" " or ";") "<more proxy information>"
      r"$",
      sProxyInformation,
    );
    assert oProxyInformationMatch, \
        "Badly formed proxy information: %s" % repr(sProxyInformation);
    (s0Scheme1, s0Scheme2, sHost, s0PortNumber) = oProxyInformationMatch.groups();
    oProxyURL = cURL(
      sProtocol = s0Scheme1 or s0Scheme2 or "http", #oURL.sbProtocol,
      sHost = sHost,
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
    o0Response = oHTTPClient.fo0GetResponseForRequestAndURL(
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
    if oSelf.__bStopping:
      fShowDebugOutput(oSelf, "Stopping.");
      return None;
    assert o0Response, \
        "Expected a response but got %s" % repr(o0Response);
    o0CookieStore = oSelf.o0CookieStore;
    if o0CookieStore: o0CookieStore.fUpdateFromResponseAndURL(o0Response, oURL);
    return o0Response;
  
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
      "selected proxy",
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
          nSendDelayPerByteInSeconds = oSelf.nSendDelayPerByteInSeconds,
          bVerifyCertificates = oSelf.__bVerifyCertificates,
          bzCheckHost = oSelf.__bzCheckHost,
        );
        oClient.fAddCallbacks({
          "server host invalid": lambda oClient, *, sbHost, oException: oSelf.fFireCallbacks(
            "server host invalid",
            oClient = oClient,
            sbHost = sbHost,
            oException = oException,
          ),
          "resolving server hostname to ip address": lambda oClient, *, sbHostname: oSelf.fFireCallbacks(
            "resolving server hostname to ip address",
            oClient = oClient,
            sbHostname = sbHostname,
          ),
          "resolving server hostname to ip address failed": lambda oClient, *, sbHostname, oException: oSelf.fFireCallbacks(
            "resolving server hostname to ip address failed",
            oClient = oClient,
            sbHostname = sbHostname,
            oException = oException,
          ),
          "resolved server hostname to ip address": lambda oClient, *, sbHostname, sbIPAddress, sCanonicalName: oSelf.fFireCallbacks(
            "resolved server hostname to ip address",
            oClient = oClient,
            sbHostname = sbHostname,
            sbIPAddress = sbIPAddress,
            sCanonicalName = sCanonicalName,
          ),
          "connecting to server": lambda oClient, *, sbHost, sbIPAddress, uPortNumber: oSelf.fFireCallbacks(
            "connecting to server",
            oClient = oClient,
            sbHost = sbHost,
            sbIPAddress = sbIPAddress,
            uPortNumber = uPortNumber,
          ),
          "connecting to server failed": lambda oClient, *, sbHost, sbIPAddress, uPortNumber, oException: oSelf.fFireCallbacks(
            "connecting to server failed",
            oClient = oClient,
            sbHost = sbHost,
            sbIPAddress = sbIPAddress,
            uPortNumber = uPortNumber,
            oException = oException,
          ),
          "created connection to server": lambda oClient, *, sbHost, sbIPAddress, uPortNumber, oConnection: oSelf.fFireCallbacks(
            "created connection to server",
            oClient = oClient,
            sbHost = sbHost,
            sbIPAddress = sbIPAddress,
            uPortNumber = uPortNumber,
            oConnection = oConnection,
          ),
          "terminated connection to server": lambda oClient, *, sbHost, sbIPAddress, uPortNumber, oConnection: oSelf.fFireCallbacks(
            "terminated connection to server",
            oClient = oClient,
            sbHost = sbHost,
            sbIPAddress = sbIPAddress,
            uPortNumber = uPortNumber, 
            oConnection = oConnection,
          ),
          "securing connection to server": lambda oClient, *, sbHost, sbIPAddress, uPortNumber, oConnection, oSSLContext: oSelf.fFireCallbacks(
            "securing connection to server",
            oClient = oClient,
            sbHost = sbHost,
            sbIPAddress = sbIPAddress,
            uPortNumber = uPortNumber,
            oConnection = oConnection,
            oSSLContext = oSSLContext,
          ),
          "securing connection to server failed": lambda oClient, *, oException, sbHost, sbIPAddress, uPortNumber, oConnection, oSSLContext: oSelf.fFireCallbacks(
            "securing connection to server failed",
            oClient = oClient,
            oException = oException,
            sbHost = sbHost,
            sbIPAddress = sbIPAddress,
            uPortNumber = uPortNumber,
            oConnection = oConnection,
            oSSLContext = oSSLContext,
          ),
          "secured connection to server": lambda oClient, *, sbHost, sbIPAddress, uPortNumber, oConnection, oSSLContext: oSelf.fFireCallbacks(
            "secured connection to server",
            oClient = oClient,
            sbHost = sbHost,
            sbIPAddress = sbIPAddress,
            uPortNumber = uPortNumber,
            oConnection = oConnection,
            oSSLContext = oSSLContext,
          ),
          "received out-of-band data from server": lambda oClient, *, oConnection, sbOutOfBandData: oSelf.fFireCallbacks(
            "received out-of-band data from server",
            oConnection = oConnection,
            sbOutOfBandData = sbOutOfBandData,
          ),
          "sending request to server": lambda oClient, *, oConnection, oRequest: oSelf.fFireCallbacks(
            "sending request to server",
            oClient = oClient,
            oConnection = oConnection,
            oRequest = oRequest,
          ),
          "sending request to server failed": lambda oClient, *, oConnection, oRequest, oException: oSelf.fFireCallbacks(
            "sending request to server failed",
            oClient = oClient,
            oConnection = oConnection,
            oRequest = oRequest,
            oException = oException,
          ),
          "sent request to server": lambda oClient, *, oConnection, oRequest: oSelf.fFireCallbacks(
            "sent request to server",
            oClient = oClient,
            oConnection = oConnection,
            oRequest = oRequest,
          ),
          "receiving response from server": lambda oClient, *, oConnection, o0Request: oSelf.fFireCallbacks(
            "receiving response from server",
            oClient = oClient,
            oConnection = oConnection,
            o0Request = o0Request,
          ),
          "receiving response from server failed": lambda oClient, *, oConnection, o0Request, oException: oSelf.fFireCallbacks(
            "receiving response from server failed",
            oClient = oClient,
            oConnection = oConnection,
            o0Request = o0Request,
            oException = oException,
          ),
          "received response from server": lambda oClient, *, oConnection, o0Request, oResponse: oSelf.fFireCallbacks(
            "received response from server",
            oClient = oClient,
            oConnection = oConnection,
            o0Request = o0Request,
            oResponse = oResponse,
          ),
          "terminated": oSelf.__fHandleTerminatedCallbackFromDirectHTTPClient,
        });
        bNewClient = True;
      else:
        oClient = oSelf.__oDirectHTTPClient;
    else:
      oProxyServerURL = o0ProxyServerURL;
      sLowerProxyServerURL = str(oProxyServerURL).lower();
      oClient = oSelf.__doHTTPClientUsingProxyServer_by_sbLowerProxyServerURL.get(sLowerProxyServerURL);
      if oClient is None:
        oClient = oSelf.__doHTTPClientUsingProxyServer_by_sbLowerProxyServerURL[sLowerProxyServerURL] = cHTTPClientUsingProxyServer(
          oProxyServerURL,
          bVerifyCertificatesForProxy = oSelf.__bVerifyCertificatesForProxy,
          bzCheckProxyHost = oSelf.__bzCheckProxyHost,
          o0zCertificateStore = oSelf.__o0CertificateStore,
          u0zMaxNumberOfConnectionsToProxy = oSelf.__u0zMaxNumberOfConnectionsToProxy,
          n0zConnectToProxyTimeoutInSeconds = oSelf.__n0zConnectToProxyTimeoutInSeconds,
          n0zSecureConnectionToProxyTimeoutInSeconds = oSelf.__n0zSecureConnectionToProxyTimeoutInSeconds,
          n0zSecureConnectionToServerTimeoutInSeconds = oSelf.__n0zSecureConnectionToServerTimeoutInSeconds,
          n0zTransactionTimeoutInSeconds = oSelf.__n0zTransactionTimeoutInSeconds,
          nSendDelayPerByteInSeconds = oSelf.nSendDelayPerByteInSeconds,
          bVerifyCertificates = oSelf.__bVerifyCertificates,
          bzCheckHost = oSelf.__bzCheckHost,
        );
        oClient.fAddCallbacks({
          "proxy host invalid": lambda oClient, *, sbHost: oSelf.fFireCallbacks(
            "proxy host invalid",
            oProxyServerURL = oProxyServerURL,
            oClient = oClient,
            sbHost = sbHost,
          ),
          "resolving proxy hostname": lambda oClient, *, sbHostname: oSelf.fFireCallbacks(
            "resolving proxy hostname",
            oProxyServerURL = oProxyServerURL,
            oClient = oClient,
            sbHostname = sbHostname,
          ),
          "resolving proxy hostname failed": lambda oClient, *, sbHostname: oSelf.fFireCallbacks(
            "resolving proxy hostname failed",
            oProxyServerURL = oProxyServerURL,
            oClient = oClient,
            sbHostname = sbHostname,
          ),
          "proxy hostname resolved to ip address": lambda oClient, *, sbHostname, sbIPAddress, sCanonicalName: oSelf.fFireCallbacks(
            "proxy hostname resolved to ip address",
            oProxyServerURL = oProxyServerURL,
            oClient = oClient,
            sbHostname = sbHostname,
            sbIPAddress = sbIPAddress,
            sCanonicalName = sCanonicalName,
          ),
          # Connecting to proxy
          "connecting to proxy": lambda oClient, *, oProxyServerURL, sbIPAddress: oSelf.fFireCallbacks(
            "connecting to proxy",
            oProxyServerURL = oProxyServerURL,
            oClient = oClient,
            sbIPAddress = sbIPAddress,
          ),
          "connecting to proxy failed": lambda oClient, *, oProxyServerURL, sbIPAddress, uPortNumber, oException: oSelf.fFireCallbacks(
            "connecting to proxy failed",
            oProxyServerURL = oProxyServerURL,
            oClient = oClient,
            sbIPAddress = sbIPAddress,
            uPortNumber = uPortNumber,
            oException = oException,
          ),
          "created connection to proxy": lambda oClient, *, oConnection, oProxyServerURL: oSelf.fFireCallbacks(
            "created connection to proxy",
            oProxyServerURL = oProxyServerURL,
            oClient = oClient,
            oConnection = oConnection,
          ),
          "terminated connection to proxy": lambda oClient, *, oConnection, oProxyServerURL: oSelf.fFireCallbacks(
            "terminated connection to proxy",
            oProxyServerURL = oProxyServerURL,
            oClient = oClient,
            oConnection = oConnection,
          ),
          # Securing connection to proxy
          "securing connection to proxy": lambda oClient, *, oConnection, oProxyServerURL, oSSLContext: oSelf.fFireCallbacks(
            "securing connection to proxy",
            oProxyServerURL = oProxyServerURL,
            oClient = oClient,
            oConnection = oConnection,
            oSSLContext = oSSLContext,
          ),
          "securing connection to proxy failed": lambda oClient, *, oConnection, oProxyServerURL, oSSLContext, oException: oSelf.fFireCallbacks(
            "securing connection to proxy failed",
            oProxyServerURL = oProxyServerURL,
            oClient = oClient,
            oConnection = oConnection,
            oSSLContext = oSSLContext,
            oException = oException,
          ),
          "secured connection to proxy": lambda oClient, *, oConnection, oProxyServerURL, oSSLContext: oSelf.fFireCallbacks(
            "secured connection to proxy",
            oProxyServerURL = oProxyServerURL,
            oClient = oClient,
            oConnection = oConnection,
            oSSLContext = oSSLContext,
          ),
          "received out-of-band data from proxy": lambda oClient, *, oConnection, sbOutOfBandData: oSelf.fFireCallbacks(
            "received out-of-band data from proxy",
            oConnection = oConnection,
            sbOutOfBandData = sbOutOfBandData,
          ),
          # Send request to proxy
          "sending request to proxy": lambda oClient, *, oConnection, oRequest: oSelf.fFireCallbacks(
            "sending request to proxy",
            oProxyServerURL = oProxyServerURL,
            oClient = oClient,
            oConnection = oConnection,
            oRequest = oRequest,
          ),
          "sending request to proxy failed": lambda oClient, *, oConnection, oRequest, oException: oSelf.fFireCallbacks(
            "sending request to proxy failed",
            oProxyServerURL = oProxyServerURL,
            oClient = oClient,
            oConnection = oConnection,
            oRequest = oRequest,
            oException = oException,
          ),
          "sent request to proxy": lambda oClient, *, oConnection, oRequest: oSelf.fFireCallbacks(
            "sent request to proxy",
            oProxyServerURL = oProxyServerURL,
            oClient = oClient,
            oConnection = oConnection,
            oRequest = oRequest,
          ),
          # Receive response from proxy
          "receiving response from proxy": lambda oClient, *, oConnection, o0Request: oSelf.fFireCallbacks(
            "receiving response from proxy",
            oProxyServerURL = oProxyServerURL,
            oClient = oClient,
            oConnection = oConnection,
            o0Request = o0Request,
          ),
          "receiving response from proxy failed": lambda oClient, *, oConnection, o0Request, oException: oSelf.fFireCallbacks(
            "receiving response from proxy failed",
            oProxyServerURL = oProxyServerURL,
            oClient = oClient,
            oConnection = oConnection,
            o0Request = o0Request,
            oException = oException,
          ),
          "received response from proxy": lambda oClient, *, oConnection, o0Request, oResponse: oSelf.fFireCallbacks(
            "received response from proxy",
            oProxyServerURL = oProxyServerURL,
            oClient = oClient,
            oConnection = oConnection,
            o0Request = o0Request,
            oResponse = oResponse,
          ),
          # Connecting to server through proxy
          "connecting to server through proxy": lambda oClient, *, oConnection, sbServerHost, uServerPortNumber: oSelf.fFireCallbacks(
            "connecting to server through proxy",
            oProxyServerURL = oProxyServerURL,
            oClient = oClient,
            oConnection = oConnection,
            sbServerHost = sbServerHost,
            uServerPortNumber = uServerPortNumber,
          ),
          "connecting to server through proxy failed": lambda oClient, *, oConnection, sbServerHost, uServerPortNumber, uStatusCode: oSelf.fFireCallbacks(
            "connecting to server through proxy failed",
            oClient = oClient,
            oProxyServerURL = oProxyServerURL,
            oConnection = oConnection,
            sbServerHost = sbServerHost,
            uServerPortNumber = uServerPortNumber,
            uStatusCode = uStatusCode,
          ),
          "created connection to server through proxy": lambda oClient, *, oConnection, sbServerHost, uServerPortNumber: oSelf.fFireCallbacks(
            "created connection to server through proxy",
            oClient = oClient,
            oProxyServerURL = oProxyServerURL,
            oConnection = oConnection,
            sbServerHost = sbServerHost,
            uServerPortNumber = uServerPortNumber,
          ),
          "terminated connection to server through proxy": lambda oClient, *, oConnection, sbServerHost, uServerPortNumber: oSelf.fFireCallbacks(
            "terminated connection to server through proxy",
            oClient = oClient,
            oProxyServerURL = oProxyServerURL,
            oConnection = oConnection,
            sbServerHost = sbServerHost,
            uServerPortNumber = uServerPortNumber,
          ),
          # Securing connection to server through proxy
          "securing connection to server through proxy": lambda oClient, *, oConnection, sbServerHost, uServerPortNumber, oSSLContext: oSelf.fFireCallbacks(
            "connection to server through proxy created",
            oClient = oClient,
            oProxyServerURL = oProxyServerURL,
            oConnection = oConnection,
            sbServerHost = sbServerHost,
            uServerPortNumber = uServerPortNumber,
            oSSLContext = oSSLContext,
          ),
          "securing connection to server through proxy failed": lambda oClient, *, oConnection, sbServerHost, uServerPortNumber, oSSLContext, oException: oSelf.fFireCallbacks(
            "securing connection to server through proxy failed",
            oProxyServerURL = oProxyServerURL,
            oClient = oClient,
            oConnection = oConnection,
            sbServerHost = sbServerHost,
            uServerPortNumber = uServerPortNumber,
            oSSLContext = oSSLContext,
            oException = oException, 
          ),
          "secured connection to server through proxy": lambda oClient, *, oConnection, sbServerHost, uServerPortNumber, oSSLContext: oSelf.fFireCallbacks(
            "secured connection to server through proxy",
            oProxyServerURL = oProxyServerURL,
            oClient = oClient,
            oConnection = oConnection,
            sbServerHost = sbServerHost,
            uServerPortNumber = uServerPortNumber,
            oSSLContext = oSSLContext,
          ),
          "terminated": oSelf.__fHandleTerminatedCallbackFromHTTPClientUsingProxyServer,
        });
        bNewClient = True;
    
    if bNewClient:
      oClient.fAddCallbacks({
        "wrote bytes": lambda oClient, *, oConnection, sbBytes: oSelf.fFireCallbacks(
          "wrote bytes",
          o0ProxyServerURL = o0ProxyServerURL,
          oClient = oClient,
          oConnection = oConnection,
          sbBytes = sbBytes,
        ),
        "read bytes": lambda oClient, *, oConnection, sbBytes: oSelf.fFireCallbacks(
          "read bytes",
          o0ProxyServerURL = o0ProxyServerURL,
          oClient = oClient,
          oConnection = oConnection,
          sbBytes = sbBytes,
        ),
      });
      oSelf.fFireCallbacks(
        "created client",
        oClient = oClient,
        o0ProxyServerURL = o0ProxyServerURL,
      );
    return oClient;
    
  def __fHandleTerminatedCallbackFromDirectHTTPClient(oSelf, oClient):
    oSelf.fFireCallbacks(
      "terminated client",
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
      "terminated client",
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
    o0CookieStore = oSelf.o0CookieStore;
    return [s for s in [
      "with%s direct client" % ("" if oSelf.__oDirectHTTPClient else "out"),
      "%s proxy clients" % (
        str(len(oSelf.__doHTTPClientUsingProxyServer_by_sbLowerProxyServerURL))
            if oSelf.__doHTTPClientUsingProxyServer_by_sbLowerProxyServerURL
        else "no"
      ),
      "stopping" if oSelf.__bStopping else None,
    ] if s] + (
      o0CookieStore.fasGetDetails() if o0CookieStore else []
    );
