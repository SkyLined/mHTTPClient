try: # mDebugOutput use is Optional
  from mDebugOutput import ShowDebugOutput, fShowDebugOutput;
except ModuleNotFoundError as oException:
  if oException.args[0] != "No module named 'mDebugOutput'":
    raise;
  ShowDebugOutput = lambda fx: fx; # NOP
  fShowDebugOutput = lambda x, s0 = None: x; # NOP

from mMultiThreading import cLock, cWithCallbacks;
from mNotProvided import \
  fbIsProvided, \
  fxGetFirstProvidedValue, \
  fxzGetFirstProvidedValueIfAny, \
  zNotProvided;
try: # SSL support is optional.
  from mSSL import cCertificateStore as c0CertificateStore;
except:
  c0CertificateStore = None; # No SSL support

from .cHTTPConnectionsToServerPool import cHTTPConnectionsToServerPool;
from .iHTTPClient import iHTTPClient;

# To turn access to data store in multiple variables into a single transaction, we will create locks.
# These locks should only ever be locked for a short time; if it is locked for too long, it is considered a "deadlock"
# bug, where "too long" is defined by the following value:
gnDeadlockTimeoutInSeconds = 10; # We may need to call openssl binaries to generate certificates, which can take a while

class cHTTPClient(iHTTPClient, cWithCallbacks):
  u0zDefaultMaxNumberOfConnectionsToServer = 10;
  n0zDefaultConnectTimeoutInSeconds = 10;
  n0zDefaultSecureTimeoutInSeconds = 5;
  n0zDefaultTransactionTimeoutInSeconds = 10;
  
  @ShowDebugOutput
  def __init__(oSelf,
    *,
    o0CookieStore = None,
    o0zCertificateStore = zNotProvided,
    u0zMaxNumberOfConnectionsToServer = zNotProvided,
    n0zConnectTimeoutInSeconds = zNotProvided,
    n0zSecureTimeoutInSeconds = zNotProvided,
    n0zTransactionTimeoutInSeconds = zNotProvided,
    nSendDelayPerByteInSeconds = 0,
    bVerifyCertificates = True,
    bzCheckHost = zNotProvided,
    dsbSpoofedHost_by_sbHost = {},
  ):
    super().__init__(
      o0CookieStore = o0CookieStore,
    );
    oSelf.__o0CertificateStore = (
      o0zCertificateStore if fbIsProvided(o0zCertificateStore) else
      c0CertificateStore() if c0CertificateStore else
      None
    );
    oSelf.__u0zMaxNumberOfConnectionsToServer = fxGetFirstProvidedValue(u0zMaxNumberOfConnectionsToServer, oSelf.u0zDefaultMaxNumberOfConnectionsToServer);
    # Timeouts can be provided through class default, instance defaults, or method call arguments.
    oSelf.__n0zConnectTimeoutInSeconds = fxzGetFirstProvidedValueIfAny(n0zConnectTimeoutInSeconds, oSelf.n0zDefaultConnectTimeoutInSeconds);
    oSelf.__n0zSecureTimeoutInSeconds = fxzGetFirstProvidedValueIfAny(n0zSecureTimeoutInSeconds, oSelf.n0zDefaultSecureTimeoutInSeconds);
    oSelf.__n0zTransactionTimeoutInSeconds = fxzGetFirstProvidedValueIfAny(n0zTransactionTimeoutInSeconds, oSelf.n0zDefaultTransactionTimeoutInSeconds);
    oSelf.__bVerifyCertificates = bVerifyCertificates;
    if bVerifyCertificates:
      oSelf.__bzCheckHost = bzCheckHost;
    else:
      assert not fbIsProvided(bzCheckHost) or not bzCheckHost, \
          "Cannot check host if certificates are not verified";
      oSelf.__bzCheckHost = False;
    oSelf.dsbSpoofedHost_by_sbHost = dsbSpoofedHost_by_sbHost;
    
    oSelf.__oPropertyAccessTransactionLock = cLock(
      "%s.__oPropertyAccessTransactionLock" % oSelf.__class__.__name__,
      n0DeadlockTimeoutInSeconds = gnDeadlockTimeoutInSeconds
    );
    oSelf.__doHTTPConnectionsToServerPool_by_sbBaseURL = {};
    
    oSelf.__bStopping = False;
    oSelf.__oTerminatedLock = cLock("%s.__oTerminatedLock" % oSelf.__class__.__name__, bLocked = True);
    oSelf.nSendDelayPerByteInSeconds = nSendDelayPerByteInSeconds;
    
    oSelf.fAddEvents(
      "spoofing server host",
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
      
      "read bytes",
      "wrote bytes",

      "sending request to server",
      "sending request to server failed",
      "sent request to server",

      "receiving response from server",
      "receiving response from server failed", 
      "received response from server",
      
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
    for oHTTPConnectionsToServerPool in oSelf.__doHTTPConnectionsToServerPool_by_sbBaseURL.values():
      oHTTPConnectionsToServerPool.fSetSendDelayPerByteInSeconds(nSendDelayPerByteInSeconds);
  
  @ShowDebugOutput
  def fStop(oSelf):
    oSelf.__oPropertyAccessTransactionLock.fAcquire();
    try:
      if oSelf.bTerminated:
        return fShowDebugOutput(oSelf, "Already terminated");
      if oSelf.__bStopping:
        return fShowDebugOutput(oSelf, "Already stopping");
      fShowDebugOutput(oSelf, "Stopping...");
      # Prevent any new cHTTPConnectionsToServerPool instances from being created.
      oSelf.__bStopping = True;
      # Grab a list of active cHTTPConnectionsToServerPool instances that need to be stopped.
      aoHTTPConnectionsToServerPools = list(oSelf.__doHTTPConnectionsToServerPool_by_sbBaseURL.values());
    finally:
      oSelf.__oPropertyAccessTransactionLock.fRelease();
    if len(aoHTTPConnectionsToServerPools) == 0:
      # We stopped when there were no connections: we are terminated.
      fShowDebugOutput(oSelf, "Terminated.");
      oSelf.__oTerminatedLock.fRelease();
      oSelf.fFireCallbacks("terminated");
    else:
      fShowDebugOutput(oSelf, "Stopping connections to server pools...");
      # Stop all cHTTPConnectionsToServerPool instances
      for oConnectionsToServerPool in aoHTTPConnectionsToServerPools:
        oConnectionsToServerPool.fStop();
  
  @ShowDebugOutput
  def fTerminate(oSelf):
    oSelf.__oPropertyAccessTransactionLock.fAcquire();
    try:
      if oSelf.bTerminated:
        return fShowDebugOutput(oSelf, "Already terminated.");
      fShowDebugOutput(oSelf, "Terminating...");
      oSelf.__bStopping = True;
      # Grab a list of active cHTTPConnectionsToServerPool instances that need to be terminated.
      aoHTTPConnectionsToServerPools = list(oSelf.__doHTTPConnectionsToServerPool_by_sbBaseURL.values());
    finally:
      oSelf.__oPropertyAccessTransactionLock.fRelease();
    # Terminate all cHTTPConnectionsToServerPool instances
    if len(aoHTTPConnectionsToServerPools) == 0:
      fShowDebugOutput(oSelf, "Terminated.");
      oSelf.__oTerminatedLock.fRelease();
      oSelf.fFireCallbacks("terminated");
    else:
      fShowDebugOutput(oSelf, "Terminating %d connections to server pools..." % len(aoHTTPConnectionsToServerPools));
      for oConnectionsToServerPool in aoHTTPConnectionsToServerPools:
        oConnectionsToServerPool.fTerminate();
  
  @ShowDebugOutput
  def fWait(oSelf):
    return oSelf.__oTerminatedLock.fWait();
  @ShowDebugOutput
  def fbWait(oSelf, nTimeoutInSeconds):
    return oSelf.__oTerminatedLock.fbWait(nTimeoutInSeconds);
  
  def fo0GetProxyServerURLForURL(oSelf, oURL):
    return None;
  
  @ShowDebugOutput
  def fo0GetResponseForRequestAndURL(oSelf,
    oRequest, 
    oURL,
    *,
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
      fShowDebugOutput(oSelf, "Stopping.");
      return None;
    oConnectionsToServerPool = oSelf.__foGetConnectionsToServerPoolForURL(oURL);
    if oSelf.__bStopping:
      fShowDebugOutput(oSelf, "Stopping.");
      return None;
    o0Response = oConnectionsToServerPool.fo0SendRequestAndReceiveResponse(
      oRequest,
      n0zConnectTimeoutInSeconds = oSelf.__n0zConnectTimeoutInSeconds,
      n0zSecureTimeoutInSeconds = oSelf.__n0zSecureTimeoutInSeconds,
      n0zTransactionTimeoutInSeconds = oSelf.__n0zTransactionTimeoutInSeconds,
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
  def fo0GetConnectionAndStartTransactionForURL(oSelf,
    oURL,
    bSecureConnection = True,
  ):
    if oSelf.__bStopping:
      fShowDebugOutput(oSelf, "Stopping.");
      return None;
    oConnectionsToServerPool = oSelf.__foGetConnectionsToServerPoolForURL(oURL);
    if oSelf.__bStopping:
      fShowDebugOutput(oSelf, "Stopping.");
      return None;
    return oConnectionsToServerPool.fo0GetConnectionAndStartTransaction(
      n0zConnectTimeoutInSeconds = oSelf.__n0zConnectTimeoutInSeconds,
      bSecureConnection = bSecureConnection,
      n0zSecureTimeoutInSeconds = oSelf.__n0zSecureTimeoutInSeconds,
      n0zTransactionTimeoutInSeconds = oSelf.__n0zTransactionTimeoutInSeconds,
    );
    
  @ShowDebugOutput
  def __foGetConnectionsToServerPoolForURL(oSelf, oURL):
    # We may need to spoof the host, which means connecting to the spoofed host
    # but otherwise acting as if it was the original (e.g. for SSL context and `Host`
    # header. We will create a `oServerBaseURL` that uniquely identifies a server using
    # the protocol, (spoofed) host and port, which will be used for connecting sockets.
    oServerBaseURL = oURL.oBase;
    sbHost = oURL.sbHost.lower();
    if sbHost in oSelf.dsbSpoofedHost_by_sbHost:
      sbSpoofedHost = oSelf.dsbSpoofedHost_by_sbHost[sbHost];
      oSelf.fFireCallbacks(
        "spoofing server host",
        sbHost = sbHost,
        sbSpoofedHost = sbSpoofedHost,
      ),
      sbHost = sbSpoofedHost;
      oServerBaseURL.sbHost = sbSpoofedHost;
    # We will use a single cHTTPConnectionsToServerPool instances for each server.
    # Servers are identified by host name, port and whether or not the connection is secure.
    # We may want to change this to identification by IP address rather than host name.
    # To prevent two threads from creating a new cHTTPConnectionsToServerPool instance for
    # the same server, getting an existing one or creating a new one is an atomic operation
    # through the 
    oSelf.__oPropertyAccessTransactionLock.fAcquire();
    try:
      o0ConnectionsToServerPool = oSelf.__doHTTPConnectionsToServerPool_by_sbBaseURL.get(oServerBaseURL.sbBase);
      if o0ConnectionsToServerPool:
        return o0ConnectionsToServerPool;
      # No connections to the server have been made before: create a new Pool.
      if oURL.bSecure and oSelf.__o0CertificateStore:
        if oSelf.__bVerifyCertificates:
          o0SSLContext = oSelf.__o0CertificateStore.foGetClientsideSSLContextForHost(
            oURL.sbHost,
          );
        else:
          o0SSLContext = oSelf.__o0CertificateStore.foGetClientsideSSLContextWithoutVerificationForHost(
            oURL.sbHost,
          );
      else:
        # The URL may either be "http://" or we will not be able to create secure connections when asked.
        o0SSLContext = None;
      fShowDebugOutput(oSelf, "Creating new cConnectionsToServerPool for %s" % oURL.sbBase);
      oConnectionsToServerPool = cHTTPConnectionsToServerPool(
        oServerBaseURL = oServerBaseURL,
        u0zMaxNumberOfConnectionsToServer = oSelf.__u0zMaxNumberOfConnectionsToServer,
        o0SSLContext = o0SSLContext,
        bzCheckHost = oSelf.__bzCheckHost,
        nSendDelayPerByteInSeconds = oSelf.nSendDelayPerByteInSeconds,
      );
      oConnectionsToServerPool.fAddCallbacks({
        "server host invalid": lambda oConnectionsToServerPool, *, sbHost: oSelf.fFireCallbacks(
          "server host invalid",
          sbHost = sbHost,
        ),
        "resolving server hostname to ip address": lambda oConnectionsToServerPool, *, sbHostname: oSelf.fFireCallbacks(
          "resolving server hostname to ip address",
          sbHostname = sbHostname,
        ),
        "resolving server hostname to ip address failed": lambda oConnectionsToServerPool, *, sbHostname: oSelf.fFireCallbacks(
          "resolving server hostname to ip address failed",
          sbHostname = sbHostname,
        ),
        "resolved server hostname to ip address": lambda oConnectionsToServerPool, *, sbHostname, sbIPAddress, sCanonicalName: oSelf.fFireCallbacks(
          "resolved server hostname to ip address",
          sbHostname = sbHostname,
          sbIPAddress = sbIPAddress,
          sCanonicalName = sCanonicalName,
        ),
        "connecting to server": lambda oConnectionsToServerPool, *, sbHost, sbIPAddress, uPortNumber: oSelf.fFireCallbacks(
          "connecting to server",
          sbHost = sbHost,
          sbIPAddress = sbIPAddress,
          uPortNumber = uPortNumber,
        ),
        "connecting to server failed": lambda oConnectionsToServerPool, *, oException, sbHost, sbIPAddress, uPortNumber: oSelf.fFireCallbacks(
          "connecting to server failed",
          oException = oException,
          sbHost = sbHost,
          sbIPAddress = sbIPAddress,
          uPortNumber = uPortNumber,
        ),
        "created connection to server": lambda oConnectionsToServerPool, *, sbHost, uPortNumber, sbIPAddress, oConnection: oSelf.fFireCallbacks(
          "created connection to server",
          sbHost = sbHost,
          uPortNumber = uPortNumber,
          sbIPAddress = sbIPAddress,
          oConnection = oConnection,
        ),
        "terminated connection to server": lambda oConnectionsToServerPool, *, sbHost, uPortNumber, sbIPAddress, oConnection: oSelf.fFireCallbacks(
          "terminated connection to server",
          sbHost = sbHost,
          sbIPAddress = sbIPAddress,
          uPortNumber = uPortNumber,
          oConnection = oConnection,
        ),
        "securing connection to server": lambda oConnectionsToServerPool, *, sbHost, sbIPAddress, uPortNumber, oConnection, oSSLContext: oSelf.fFireCallbacks(
          "securing connection to server",
          sbHost = sbHost,
          sbIPAddress = sbIPAddress,
          uPortNumber = uPortNumber,
          oConnection = oConnection,
          oSSLContext = oSSLContext,
        ),
        "securing connection to server failed": lambda oConnectionsToServerPool, *, oException, sbHost, sbIPAddress, uPortNumber, oConnection, oSSLContext: oSelf.fFireCallbacks(
          "securing connection to server failed",
          oException = oException,
          sbHost = sbHost,
          sbIPAddress = sbIPAddress,
          uPortNumber = uPortNumber,
          oConnection = oConnection,
          oSSLContext = oSSLContext,
        ),
        "secured connection to server": lambda oConnectionsToServerPool, *, sbHost, sbIPAddress, uPortNumber, oConnection, oSSLContext: oSelf.fFireCallbacks(
          "secured connection to server",
          sbHost = sbHost,
          sbIPAddress = sbIPAddress,
          uPortNumber = uPortNumber,
          oConnection = oConnection,
          oSSLContext = oSSLContext,
        ),
        "read bytes": lambda oConnectionsToServerPool, *, oConnection, sbBytes: oSelf.fFireCallbacks(
          "read bytes",
          oConnection = oConnection,
          sbBytes = sbBytes,
        ),
        "wrote bytes": lambda oConnectionsToServerPool, *, oConnection, sbBytes: oSelf.fFireCallbacks(
          "wrote bytes",
          oConnection = oConnection,
          sbBytes = sbBytes,
        ),
        "sending request to server": lambda oConnectionsToServerPool, *, oConnection, oRequest: oSelf.fFireCallbacks(
          "sending request to server",
          oConnection = oConnection,
          oRequest = oRequest,
        ),
        "sending request to server failed": lambda oConnectionsToServerPool, *, oConnection, oRequest, oException: oSelf.fFireCallbacks(
          "sending request to server failed",
          oConnection = oConnection,
          oRequest = oRequest,
          oException = oException,
        ),
        "sent request to server": lambda oConnectionsToServerPool, *, oConnection, oRequest: oSelf.fFireCallbacks(
          "sent request to server",
          oConnection = oConnection,
          oRequest = oRequest,
        ),
        "receiving response from server": lambda oConnectionsToServerPool, *, oConnection, o0Request: oSelf.fFireCallbacks(
          "receiving response from server",
          oConnection = oConnection,
          o0Request = o0Request,
        ),
        "receiving response from server failed": lambda oConnectionsToServerPool, *, oConnection, o0Request, oException: oSelf.fFireCallbacks(
          "receiving response from server failed",
          oConnection = oConnection,
          o0Request = o0Request,
          oException = oException,
        ),
        "received response from server": lambda oConnectionsToServerPool, *, oConnection, o0Request, oResponse: oSelf.fFireCallbacks(
          "received response from server",
          oConnection = oConnection,
          o0Request = o0Request,
          oResponse = oResponse,
        ),
        "terminated": oSelf.__fHandleTerminatedCallbackForConnectionsToServerPool,
      });
      oSelf.__doHTTPConnectionsToServerPool_by_sbBaseURL[oServerBaseURL.sbBase] = oConnectionsToServerPool;
    finally:
      oSelf.__oPropertyAccessTransactionLock.fRelease();
    return oConnectionsToServerPool;
  
  @ShowDebugOutput
  def __fHandleTerminatedCallbackForConnectionsToServerPool(oSelf, oConnectionsToServerPool):
    assert oSelf.__bStopping, \
        "This is really unexpected!";
    oSelf.__oPropertyAccessTransactionLock.fAcquire();
    try:
      for sbBaseURL in oSelf.__doHTTPConnectionsToServerPool_by_sbBaseURL:
        if oSelf.__doHTTPConnectionsToServerPool_by_sbBaseURL[sbBaseURL] == oConnectionsToServerPool:
          fShowDebugOutput(oSelf, "Removing cConnectionsToServerPool for %s" % sbBaseURL);
          del oSelf.__doHTTPConnectionsToServerPool_by_sbBaseURL[sbBaseURL];
          break;
      else:
        raise AssertionError("A cConnectionsToServerPool instance reported that it terminated, but we were not aware it existed");
      # Return if we are not stopping or if there are other connections open:
      if not oSelf.__bStopping:
        return;
      if len(oSelf.__doHTTPConnectionsToServerPool_by_sbBaseURL) > 0:
        fShowDebugOutput(oSelf, "There are %d connections to server pools left." % len(oSelf.__doHTTPConnectionsToServerPool_by_sbBaseURL));
        return;
    finally:
      oSelf.__oPropertyAccessTransactionLock.fRelease();
    # We are stopping and the last connection just terminated: we are terminated.
    fShowDebugOutput(oSelf, "Terminated.");
    oSelf.__oTerminatedLock.fRelease();
    oSelf.fFireCallbacks("terminated");
  
  def fasGetDetails(oSelf):
    # This is done without a property lock, so race-conditions exist and it
    # approximates the real values.
    if oSelf.bTerminated:
      return ["terminated"];
    o0CookieStore = oSelf.o0CookieStore;
    return [s for s in [
      "connected to %d servers" % len(oSelf.__doHTTPConnectionsToServerPool_by_sbBaseURL),
      "stopping" if oSelf.__bStopping else None,
    ] if s] + (
      o0CookieStore.fasGetDetails() if o0CookieStore else []
    );
