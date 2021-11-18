import re;

from mWindowsSDK.mWinHTTP import *;

try: # mDebugOutput use is Optional
  from mDebugOutput import ShowDebugOutput, fShowDebugOutput;
except ModuleNotFoundError as oException:
  if oException.args[0] != "No module named 'mDebugOutput'":
    raise;
  ShowDebugOutput = fShowDebugOutput = lambda x: x; # NOP

from mMultiThreading import cLock, cWithCallbacks;
from mHTTPProtocol import cURL;
from mNotProvided import *;
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
    bAllowUnverifiableCertificatesForProxy = False, bCheckProxyHostname = True,
    u0zMaxNumberOfConnectionsToServerWithoutProxy = zNotProvided,
    u0zMaxNumberOfConnectionsToProxy = zNotProvided,
    n0zConnectTimeoutInSeconds = zNotProvided, n0zSecureTimeoutInSeconds = zNotProvided, n0zTransactionTimeoutInSeconds = zNotProvided,
    n0zConnectToProxyTimeoutInSeconds = zNotProvided, n0zSecureConnectionToProxyTimeoutInSeconds = zNotProvided,
    n0zSecureConnectionToServerTimeoutInSeconds = zNotProvided,
    bAllowUnverifiableCertificates = False, bCheckHostname = True,
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
    oSelf.__bAllowUnverifiableCertificatesForProxy = bAllowUnverifiableCertificatesForProxy;
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
    oSelf.__bAllowUnverifiableCertificates = bAllowUnverifiableCertificates;
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
      "new direct client", "new client using proxy server",
      "connect failed", "new connection",
      "bytes written", "bytes read",
      "request sent", "response received", "request sent and response received",
      "secure connection established",
      "connection terminated",
      "direct client terminated", "client using proxy server terminated",
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
    oSelf.fFireCallbacks("proxy selected", oURL, o0ProxyServerURL);
    bNewClient = False;
    if o0ProxyServerURL is None:
      if oSelf.__oDirectHTTPClient is None:
        oHTTPClient = oSelf.__oDirectHTTPClient = cHTTPClient(
          o0zCertificateStore = oSelf.__o0CertificateStore,
          u0zMaxNumberOfConnectionsToServer = oSelf.__u0zMaxNumberOfConnectionsToServerWithoutProxy,
          n0zConnectTimeoutInSeconds = oSelf.__n0zConnectTimeoutInSeconds,
          n0zSecureTimeoutInSeconds = oSelf.__n0zSecureTimeoutInSeconds,
          n0zTransactionTimeoutInSeconds = oSelf.__n0zTransactionTimeoutInSeconds,
          bAllowUnverifiableCertificates = oSelf.__bAllowUnverifiableCertificates,
          bCheckHostname = oSelf.__bCheckHostname,
        );
        oHTTPClient.fAddCallback("terminated", oSelf.__fHandleTerminatedCallbackFromDirectHTTPClient);
        oSelf.fFireCallbacks("new direct client", oHTTPClient);
        bNewClient = True;
      else:
        oHTTPClient = oSelf.__oDirectHTTPClient;
    else:
      sLowerProxyServerURL = str(o0ProxyServerURL).lower();
      oHTTPClient = oSelf.__doHTTPClientUsingProxyServer_by_sbLowerProxyServerURL.get(sLowerProxyServerURL);
      if oHTTPClient is None:
        oHTTPClient = oSelf.__doHTTPClientUsingProxyServer_by_sbLowerProxyServerURL[sLowerProxyServerURL] = cHTTPClientUsingProxyServer(
          o0ProxyServerURL,
          bAllowUnverifiableCertificatesForProxy = oSelf.__bAllowUnverifiableCertificatesForProxy,
          bCheckProxyHostname = oSelf.__bCheckProxyHostname,
          o0zCertificateStore = oSelf.__o0CertificateStore,
          u0zMaxNumberOfConnectionsToProxy = oSelf.__u0zMaxNumberOfConnectionsToProxy,
          n0zConnectToProxyTimeoutInSeconds = oSelf.__n0zConnectToProxyTimeoutInSeconds,
          n0zSecureConnectionToProxyTimeoutInSeconds = oSelf.__n0zSecureConnectionToProxyTimeoutInSeconds,
          n0zSecureConnectionToServerTimeoutInSeconds = oSelf.__n0zSecureConnectionToServerTimeoutInSeconds,
          n0zTransactionTimeoutInSeconds = oSelf.__n0zTransactionTimeoutInSeconds,
          bAllowUnverifiableCertificates = oSelf.__bAllowUnverifiableCertificates,
          bCheckHostname = oSelf.__bCheckHostname,
        );
        oHTTPClient.fAddCallback("terminated", oSelf.__fHandleTerminatedCallbackFromHTTPClientUsingProxyServer);
        oSelf.fFireCallbacks("new client using proxy server", oHTTPClient);
        bNewClient = True;
    
    if bNewClient:
      oHTTPClient.fAddCallback("connect failed", oSelf.__fHandleConnectFailedCallbackFromHTTPClient);
      oHTTPClient.fAddCallback("new connection", oSelf.__fHandleNewConnectionCallbackFromHTTPClient);
      oHTTPClient.fAddCallback("bytes written", oSelf.__fHandleBytesWrittenCallbackFromHTTPClient);
      oHTTPClient.fAddCallback("bytes read", oSelf.__fHandleBytesReadCallbackFromHTTPClient);
      oHTTPClient.fAddCallback("request sent", oSelf.__fHandleRequestSentCallbackFromHTTPClient);
      oHTTPClient.fAddCallback("response received", oSelf.__fHandleResponseReceivedCallbackFromHTTPClient);
      oHTTPClient.fAddCallback("request sent and response received", oSelf.__fHandleRequestSentAndResponseReceivedCallbackFromHTTPClient);
      oHTTPClient.fAddCallback("connection terminated", oSelf.__fHandleConnectionTerminatedCallbackFromHTTPClient);
    return oHTTPClient;
  
  def __fHandleConnectFailedCallbackFromHTTPClient(oSelf, oHTTPClient, sHostname, uPortNumber, oException):
    oSelf.fFireCallbacks("connect failed", oHTTPClient, sHostname, uPortNumber, oException);
  def __fHandleNewConnectionCallbackFromHTTPClient(oSelf, oHTTPClient, oConnection):
    oSelf.fFireCallbacks("new connection", oHTTPClient, oConnection);
  def __fHandleBytesWrittenCallbackFromHTTPClient(oSelf, oHTTPClient, oConnection, sbBytesWritten):
    o0ProxyURL = None if oHTTPClient is oSelf.__oDirectHTTPClient else oHTTPClient.oProxyServerURL;
    oSelf.fFireCallbacks("bytes written", oHTTPClient, o0ProxyURL, oConnection, sbBytesWritten);
  def __fHandleBytesReadCallbackFromHTTPClient(oSelf, oHTTPClient, oConnection, sbBytesRead):
    o0ProxyURL = None if oHTTPClient is oSelf.__oDirectHTTPClient else oHTTPClient.oProxyServerURL;
    oSelf.fFireCallbacks("bytes read", oHTTPClient, o0ProxyURL, oConnection, sbBytesRead);
  def __fHandleRequestSentCallbackFromHTTPClient(oSelf, oHTTPClient, oConnection, oRequest):
    o0ProxyURL = None if oHTTPClient is oSelf.__oDirectHTTPClient else oHTTPClient.oProxyServerURL;
    oSelf.fFireCallbacks("request sent", oHTTPClient, o0ProxyURL, oConnection, oRequest);
  def __fHandleResponseReceivedCallbackFromHTTPClient(oSelf, oHTTPClient, oConnection, oReponse):
    o0ProxyURL = None if oHTTPClient is oSelf.__oDirectHTTPClient else oHTTPClient.oProxyServerURL;
    oSelf.fFireCallbacks("response received", oHTTPClient, o0ProxyURL, oConnection, oReponse);
  def __fHandleRequestSentAndResponseReceivedCallbackFromHTTPClient(oSelf, oHTTPClient, oConnection, oRequest, oReponse):
    o0ProxyURL = None if oHTTPClient is oSelf.__oDirectHTTPClient else oHTTPClient.oProxyServerURL;
    oSelf.fFireCallbacks("request sent and response received", oHTTPClient, o0ProxyURL, oConnection, oRequest, oReponse);
  def __fHandleConnectionTerminatedCallbackFromHTTPClient(oSelf, oHTTPClient, oConnection):
    oSelf.fFireCallbacks("connection terminated", oHTTPClient, oConnection);
    
  def __fHandleTerminatedCallbackFromDirectHTTPClient(oSelf, oHTTPClient):
    oSelf.fFireCallbacks("direct client terminated", oHTTPClient);
    oSelf.__oPropertyAccessTransactionLock.fAcquire();
    try:
      oSelf.__oDirectHTTPClient = None;
      # Return if we are not stopping or if there are other connections open:
      if not oSelf.__bStopping:
        return;
      if oSelf.__doHTTPClientUsingProxyServer_by_sbLowerProxyServerURL:
        return;
    finally:
      oSelf.__oPropertyAccessTransactionLock.fRelease();
    # We are stopping and the last connection just terminated: we are terminated.
    fShowDebugOutput("Terminated.");
    oSelf.__oTerminatedLock.fRelease();
    oSelf.fFireCallbacks("terminated");
  
  def __fHandleTerminatedCallbackFromHTTPClientUsingProxyServer(oSelf, oHTTPClient):
    oSelf.fFireCallbacks("client using proxy server terminated", oHTTPClient);
    oSelf.__oPropertyAccessTransactionLock.fAcquire();
    try:
      for sbURL in oSelf.__doHTTPClientUsingProxyServer_by_sbLowerProxyServerURL:
        if oSelf.__doHTTPClientUsingProxyServer_by_sbLowerProxyServerURL[sbURL] == oHTTPClient:
          del oSelf.__doHTTPClientUsingProxyServer_by_sbLowerProxyServerURL[sbURL];
          break;
      # Return if we are not stopping or if there are other connections open:
      if not oSelf.__bStopping:
        return;
      if oSelf.__oDirectHTTPClient:
        return;
      if oSelf.__doHTTPClientUsingProxyServer_by_sbLowerProxyServerURL:
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
      "direct client" if oSelf.__oDirectHTTPClient else None,
      "%d proxy clients" % (len(oSelf.__doHTTPClientUsingProxyServer_by_sbLowerProxyServerURL),) if oSelf.__doHTTPClientUsingProxyServer_by_sbLowerProxyServerURL else None,
      "stopping" if oSelf.__bStopping else None,
    ] if s];

for cException in acExceptions:
  setattr(cHTTPClientUsingAutomaticProxyServer, cException.__name__, cException);
