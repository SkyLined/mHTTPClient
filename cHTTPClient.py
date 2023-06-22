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
gnDeadlockTimeoutInSeconds = 1; # We're not doing anything time consuming, so this should suffice.

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
    bVerifyCertificates = True,
    bzCheckHostname = zNotProvided,
    f0ResolveHostnameCallback = None,
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
      oSelf.__bzCheckHostname = bzCheckHostname;
    else:
      assert not fbIsProvided(bzCheckHostname) or not bzCheckHostnamem, \
          "Cannot check hostname if certificates are not verified";
      oSelf.__bzCheckHostname = False;
    oSelf.__f0ResolveHostnameCallback = f0ResolveHostnameCallback;
    
    oSelf.__oPropertyAccessTransactionLock = cLock(
      "%s.__oPropertyAccessTransactionLock" % oSelf.__class__.__name__,
      n0DeadlockTimeoutInSeconds = gnDeadlockTimeoutInSeconds
    );
    oSelf.__doConnectionsToServerPool_by_sbProtocolHostPort = {};
    
    oSelf.__bStopping = False;
    oSelf.__oTerminatedLock = cLock("%s.__oTerminatedLock" % oSelf.__class__.__name__, bLocked = True);
    
    oSelf.fAddEvents(
      "server hostname or ip address invalid", 
      "resolving server hostname", "resolving server hostname failed", "server hostname resolved to ip address",
      
      "connecting to server ip address", "connecting to server ip address failed",
      "connecting to server failed", "connection to server created", "connection to server terminated",
      
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
        return fShowDebugOutput(oSelf, "Already terminated");
      if oSelf.__bStopping:
        return fShowDebugOutput(oSelf, "Already stopping");
      fShowDebugOutput(oSelf, "Stopping...");
      # Prevent any new cHTTPConnectionsToServerPool instances from being created.
      oSelf.__bStopping = True;
      # Grab a list of active cHTTPConnectionsToServerPool instances that need to be stopped.
      aoConnectionsToServerPools = list(oSelf.__doConnectionsToServerPool_by_sbProtocolHostPort.values())
    finally:
      oSelf.__oPropertyAccessTransactionLock.fRelease();
    if len(aoConnectionsToServerPools) == 0:
      # We stopped when there were no connections: we are terminated.
      fShowDebugOutput(oSelf, "Terminated.");
      oSelf.__oTerminatedLock.fRelease();
      oSelf.fFireCallbacks("terminated");
    else:
      fShowDebugOutput(oSelf, "Stopping connections to server pools...");
      # Stop all cHTTPConnectionsToServerPool instances
      for oConnectionsToServerPool in aoConnectionsToServerPools:
        oConnectionsToServerPool.fStop();
  
  @property
  def bTerminated(oSelf):
    return not oSelf.__oTerminatedLock.bLocked;
  
  @ShowDebugOutput
  def fTerminate(oSelf):
    oSelf.__oPropertyAccessTransactionLock.fAcquire();
    try:
      if oSelf.bTerminated:
        return fShowDebugOutput(oSelf, "Already terminated.");
      fShowDebugOutput(oSelf, "Terminating...");
      oSelf.__bStopping = True;
      # Grab a list of active cHTTPConnectionsToServerPool instances that need to be terminated.
      aoConnectionsToServerPools = list(oSelf.__doConnectionsToServerPool_by_sbProtocolHostPort.values());
    finally:
      oSelf.__oPropertyAccessTransactionLock.fRelease();
    # Terminate all cHTTPConnectionsToServerPool instances
    if len(aoConnectionsToServerPools) == 0:
      fShowDebugOutput(oSelf, "Terminated.");
      oSelf.__oTerminatedLock.fRelease();
      oSelf.fFireCallbacks("terminated");
    else:
      fShowDebugOutput(oSelf, "Terminating %d connections to server pools..." % len(aoConnectionsToServerPools));
      for oConnectionsToServerPool in aoConnectionsToServerPools:
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
    # We will reuse connections to the same server if possible. Servers are identified by host name, port and whether
    # or not the connection is secure. We may want to change this to identification by IP address rather than host name.
    oSelf.__oPropertyAccessTransactionLock.fAcquire();
    try:
      oConnectionsToServerPool = oSelf.__doConnectionsToServerPool_by_sbProtocolHostPort.get(oURL.sbBase);
      if oConnectionsToServerPool:
        return oConnectionsToServerPool;
      # No connections to the server have been made before: create a new Pool.
      if oURL.bSecure and oSelf.__o0CertificateStore:
        if oSelf.__bVerifyCertificates:
          o0SSLContext = oSelf.__o0CertificateStore.foGetClientsideSSLContextForHostname(
            oURL.sbHostname,
          );
        else:
          o0SSLContext = oSelf.__o0CertificateStore.foGetClientsideSSLContextWithoutVerification();
      else:
        # The URL may either be "http://" or we will not be able to create secure connections when asked.
        o0SSLContext = None;
      fShowDebugOutput(oSelf, "Creating new cConnectionsToServerPool for %s" % oURL.sbBase);
      oConnectionsToServerPool = cHTTPConnectionsToServerPool(
        oServerBaseURL = oURL.oBase,
        u0zMaxNumberOfConnectionsToServer = oSelf.__u0zMaxNumberOfConnectionsToServer,
        o0SSLContext = o0SSLContext,
        bzCheckHostname = oSelf.__bzCheckHostname,
      );
      oConnectionsToServerPool.fAddCallbacks({
        "server hostname or ip address invalid": lambda oConnectionsToServerPool, sbHostnameOrIPAddress: oSelf.fFireCallbacks(
          "server hostname or ip address invalid",
          sbHostnameOrIPAddress = sbHostnameOrIPAddress,
        ),
        "resolving server hostname": lambda oConnectionsToServerPool, sbHostname: oSelf.fFireCallbacks(
          "resolving server hostname",
          sbHostname = sbHostname,
        ),
        "resolving server hostname failed": lambda oConnectionsToServerPool, sbHostname: oSelf.fFireCallbacks(
          "resolving server hostname failed",
          sbHostname = sbHostname,
        ),
        "server hostname resolved to ip address": lambda oConnectionsToServerPool, sbHostname, sIPAddress, sCanonicalName: oSelf.fFireCallbacks(
          "server hostname resolved to ip address",
          sbHostname = sbHostname,
          sIPAddress = sIPAddress,
          sCanonicalName = sCanonicalName,
        ),
        "connecting to server ip address": lambda oConnectionsToServerPool, sbHostnameOrIPAddress, sIPAddress, uPortNumber, sbzHostname: oSelf.fFireCallbacks(
          "connecting to server ip address",
          sbHostnameOrIPAddress = sbHostnameOrIPAddress,
          sIPAddress = sIPAddress,
          uPortNumber = uPortNumber,
          sbzHostname = sbzHostname,
        ),
        "connecting to server ip address failed": lambda oConnectionsToServerPool, oException, sbHostnameOrIPAddress, sIPAddress, uPortNumber, sbzHostname: oSelf.fFireCallbacks(
          "connecting to server ip address failed",
          oException = oException,
          sbHostnameOrIPAddress = sbHostnameOrIPAddress,
          sIPAddress = sIPAddress,
          uPortNumber = uPortNumber,
          sbzHostname = sbzHostname,
        ),
        "connecting to server failed": lambda oConnectionsToServerPool, sbHostnameOrIPAddress, uPortNumber, oException: oSelf.fFireCallbacks(
          "connecting to server failed",
          sbHostnameOrIPAddress = sbHostnameOrIPAddress,
          uPortNumber = uPortNumber,
          oException = oException,
        ),
        "connection to server created": lambda oConnectionsToServerPool, oConnection, sbHostnameOrIPAddress: oSelf.fFireCallbacks(
          "connection to server created",
          oConnection = oConnection,
          sbHostnameOrIPAddress = sbHostnameOrIPAddress,
        ),
        "bytes read": lambda oConnectionsToServerPool, oConnection, sbBytesRead: oSelf.fFireCallbacks(
          "bytes read",
          oConnection = oConnection,
          sbBytesRead = sbBytesRead,
        ),
        "bytes written": lambda oConnectionsToServerPool, oConnection, sbBytesWritten: oSelf.fFireCallbacks(
          "bytes written", oConnection, sbBytesWritten,
        ),
        "request sent": lambda oConnectionsToServerPool, oConnection, oRequest: oSelf.fFireCallbacks(
          "request sent",
          oConnection = oConnection,
          oRequest = oRequest,
        ),
        "response received": lambda oConnectionsToServerPool, oConnection, oResponse: oSelf.fFireCallbacks(
          "response received",
          oConnection = oConnection,
          oResponse = oResponse,
        ),
        "request sent and response received": lambda oConnectionsToServerPool, oConnection, oRequest, oResponse: oSelf.fFireCallbacks(
          "request sent and response received",
          oConnection = oConnection,
          oRequest = oRequest,
          oResponse = oResponse,
        ),
        "connection to server terminated": lambda oConnectionsToServerPool, oConnection, sbHostnameOrIPAddress: oSelf.fFireCallbacks(
          "connection to server terminated",
          oConnection = oConnection,
          sbHostnameOrIPAddress = sbHostnameOrIPAddress,
        ),
        "terminated": oSelf.__fHandleTerminatedCallbackForConnectionsToServerPool,
      });
      oSelf.__doConnectionsToServerPool_by_sbProtocolHostPort[oURL.sbBase] = oConnectionsToServerPool;
      return oConnectionsToServerPool;
    finally:
      oSelf.__oPropertyAccessTransactionLock.fRelease();
  
  @ShowDebugOutput
  def __fHandleTerminatedCallbackForConnectionsToServerPool(oSelf, oConnectionsToServerPool):
    assert oSelf.__bStopping, \
        "This is really unexpected!";
    oSelf.__oPropertyAccessTransactionLock.fAcquire();
    try:
      for sbProtocolHostPort in oSelf.__doConnectionsToServerPool_by_sbProtocolHostPort:
        if oSelf.__doConnectionsToServerPool_by_sbProtocolHostPort[sbProtocolHostPort] == oConnectionsToServerPool:
          fShowDebugOutput(oSelf, "Removing cConnectionsToServerPool for %s" % sbProtocolHostPort);
          del oSelf.__doConnectionsToServerPool_by_sbProtocolHostPort[sbProtocolHostPort];
          break;
      else:
        raise AssertionError("A cConnectionsToServerPool instance reported that it terminated, but we were not aware it existed");
      # Return if we are not stopping or if there are other connections open:
      if not oSelf.__bStopping:
        return;
      if len(oSelf.__doConnectionsToServerPool_by_sbProtocolHostPort) > 0:
        fShowDebugOutput(oSelf, "There are %d connections to server pools left." % len(oSelf.__doConnectionsToServerPool_by_sbProtocolHostPort));
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
      "connected to %d servers" % len(oSelf.__doConnectionsToServerPool_by_sbProtocolHostPort),
      "stopping" if oSelf.__bStopping else None,
    ] if s] + (
      o0CookieStore.fasGetDetails() if o0CookieStore else []
    );
