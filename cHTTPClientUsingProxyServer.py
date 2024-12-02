import time;

try: # mDebugOutput use is Optional
  from mDebugOutput import ShowDebugOutput, fShowDebugOutput;
except ModuleNotFoundError as oException:
  if oException.args[0] != "No module named 'mDebugOutput'":
    raise;
  ShowDebugOutput = lambda fx: fx; # NOP
  fShowDebugOutput = lambda x, s0 = None: x; # NOP

from mMultiThreading import cLock, cWithCallbacks;
from mHTTPConnection import cHTTPConnection, cHTTPRequest, cHTTPHeaders;
from mNotProvided import \
    fbIsProvided, \
    fxGetFirstProvidedValue, \
    fxzGetFirstProvidedValueIfAny, \
    zNotProvided;
try: # SSL support is optional.
  import mSSL as m0SSL;
except:
  m0SSL = None; # No SSL support

from .iHTTPClient import iHTTPClient;
from .mExceptions import \
    cHTTPMaxConnectionsToServerReachedException, \
    cHTTPClientFailedToConnectToServerThroughProxyException, \
    cTCPIPConnectionCannotBeUsedConcurrentlyException;

# To turn access to data store in multiple variables into a single transaction, we will create locks.
# These locks should only ever be locked for a short time; if it is locked for too long, it is considered a "deadlock"
# bug, where "too long" is defined by the following value:
gnDeadlockTimeoutInSeconds = 1; # We're not doing anything time consuming, so this should suffice.

class cHTTPClientUsingProxyServer(iHTTPClient, cWithCallbacks):
  # Some sane limitation on the number of connections to the proxy makes sense, to reduce the risk of a bug in the
  # code causing an excessive number of connections to be made:
  u0DefaultMaxNumberOfConnectionsToProxy = 10;
  # The following defaults can be used to override the defaults from the mHTTPConnection classes.
  # If they are set to `zNotProvided`, the defaults from the mHTTPConnection classes will be used.
  n0zDefaultConnectToProxyTimeoutInSeconds = zNotProvided;
  n0zDefaultSecureConnectionToProxyTimeoutInSeconds = zNotProvided;
  n0zDefaultSecureConnectionToServerTimeoutInSeconds = zNotProvided;
  # There is no default transaction timeout in the mHTTPConnection classes, so this cannot be zNotProvided.
  n0DefaultTransactionTimeoutInSeconds = 10;
  
  @ShowDebugOutput
  def __init__(oSelf,
    oProxyServerURL,
    *,
    bVerifyCertificatesForProxy = True,
    bzCheckProxyHost = zNotProvided,
    o0CookieStore = None,
    o0zCertificateStore = zNotProvided,
    u0zMaxNumberOfConnectionsToProxy = zNotProvided,
    n0zConnectToProxyTimeoutInSeconds = zNotProvided,
    n0zSecureConnectionToProxyTimeoutInSeconds = zNotProvided,
    n0zSecureConnectionToServerTimeoutInSeconds = zNotProvided,
    n0zTransactionTimeoutInSeconds = zNotProvided,
    nSendDelayPerByteInSeconds = 0,
    bVerifyCertificates = True,
    bzCheckHost = zNotProvided,
  ):
    super().__init__(
      o0CookieStore = o0CookieStore,
    );
    oSelf.oProxyServerURL = oProxyServerURL;
    oSelf.__bVerifyCertificatesForProxy = bVerifyCertificatesForProxy; # Not implemented!
    oSelf.__bzCheckProxyHost = bzCheckProxyHost;
    
    oSelf.__o0CertificateStore = (
      o0zCertificateStore if fbIsProvided(o0zCertificateStore) else
      m0SSL.cCertificateStore() if m0SSL is not None else
      None
    );
    assert not oProxyServerURL.bSecure or oSelf.__o0CertificateStore, \
        "Cannot use a secure proxy without the mSSL module!";
    oSelf.__u0MaxNumberOfConnectionsToProxy = fxGetFirstProvidedValue(u0zMaxNumberOfConnectionsToProxy, oSelf.u0DefaultMaxNumberOfConnectionsToProxy);
    # Timeouts for this instance default to the timeouts specified for the class.
    oSelf.__n0zConnectToProxyTimeoutInSeconds = fxzGetFirstProvidedValueIfAny(n0zConnectToProxyTimeoutInSeconds, oSelf.n0zDefaultConnectToProxyTimeoutInSeconds);
    oSelf.__n0zSecureConnectionToProxyTimeoutInSeconds = fxzGetFirstProvidedValueIfAny(n0zSecureConnectionToProxyTimeoutInSeconds, oSelf.n0zDefaultSecureConnectionToProxyTimeoutInSeconds);
    oSelf.__n0zSecureConnectionToServerTimeoutInSeconds = fxzGetFirstProvidedValueIfAny(n0zSecureConnectionToServerTimeoutInSeconds, oSelf.n0zDefaultSecureConnectionToServerTimeoutInSeconds);
    oSelf.__n0TransactionTimeoutInSeconds = fxGetFirstProvidedValue(n0zTransactionTimeoutInSeconds, oSelf.n0DefaultTransactionTimeoutInSeconds);
    oSelf.__bVerifyCertificates = bVerifyCertificates;
    oSelf.__bzCheckHost = bzCheckHost;
    
    if not oProxyServerURL.bSecure:
      oSelf.__o0ProxySSLContext = None;
    else:
      assert oSelf.__o0CertificateStore, \
          "A secure proxy cannot be used if no certificate store is available!";
      if bVerifyCertificatesForProxy:
        oSelf.__o0ProxySSLContext = oSelf.__o0CertificateStore.foGetClientsideSSLContextForHost(
          oProxyServerURL.sbHost,
        );
      else:
        oSelf.__o0ProxySSLContext = oSelf.__o0CertificateStore.foGetClientsideSSLContextWithoutVerificationForHost(
          oProxyServerURL.sbHost,
        );
    
    oSelf.__oWaitingForConnectionToBecomeAvailableLock = cLock(
      "%s.__oWaitingForConnectionToBecomeAvailableLock" % oSelf.__class__.__name__,
    );
    
    oSelf.__oPropertyAccessTransactionLock = cLock(
      "%s.__oPropertyAccessTransactionLock" % oSelf.__class__.__name__,
      n0DeadlockTimeoutInSeconds = gnDeadlockTimeoutInSeconds
    );
    oSelf.__aoConnectionsToProxyNotConnectedToAServer = [];
    oSelf.__doSecureConnectionToServerThroughProxy_by_sbProtocolHostPort = {};
    oSelf.__doExternalizedConnectionToServerThroughProxy_by_sbProtocolHostPort = {};
    
    oSelf.__bStopping = False;
    oSelf.__oTerminatedLock = cLock(
      "%s.__oTerminatedLock" % oSelf.__class__.__name__,
      bLocked = True
    );
    oSelf.nSendDelayPerByteInSeconds = nSendDelayPerByteInSeconds;
    
    oSelf.fAddEvents(
      "proxy host invalid",
      "resolving proxy hostname to ip address",
      "resolving proxy hostname to ip address failed",
      "resolved proxy hostname to ip address",
      
      "connecting to proxy",
      "connecting to proxy failed",
      "created connection to proxy",
      "terminated connection to proxy",
      
      "securing connection to proxy",
      "securing connection to proxy failed",
      "secured connection to proxy",
      
      "read bytes",
      "wrote bytes",
      
      "sending request to proxy",
      "sending request to proxy failed",
      "sent request to proxy",

      "receiving response from proxy",
      "receiving response from proxy failed",
      "received response from proxy",
      
      "connecting to server through proxy",
      "connecting to server through proxy failed",
      "created connection to server through proxy",
      "terminated connection to server through proxy",
      
      "securing connection to server through proxy",
      "securing connection to server through proxy failed", 
      "secured connection to server through proxy",
      
      "terminated",
    );
  
  def __faoGetAllNonExternalConnections(oSelf):
    return (
      oSelf.__aoConnectionsToProxyNotConnectedToAServer
      + list(oSelf.__doSecureConnectionToServerThroughProxy_by_sbProtocolHostPort.values())
    );
  def __faoGetAllConnections(oSelf):
    return (
      oSelf.__faoGetAllNonExternalConnections()
      + list(oSelf.__doExternalizedConnectionToServerThroughProxy_by_sbProtocolHostPort.values())
    );
  
  def __fuCountAllConnections(oSelf):
    return (
      len(oSelf.__aoConnectionsToProxyNotConnectedToAServer) +
      len(oSelf.__doSecureConnectionToServerThroughProxy_by_sbProtocolHostPort) +
      len(oSelf.__doExternalizedConnectionToServerThroughProxy_by_sbProtocolHostPort)
    );
  
  @property
  def bStopping(oSelf):
    return oSelf.__bStopping;
  
  @property
  def bTerminated(oSelf):
    return not oSelf.__oTerminatedLock.bLocked;
  
  def fSetSendDelayPerByteInSeconds(oSelf, nSendDelayPerByteInSeconds):
    oSelf.nSendDelayPerByteInSeconds = nSendDelayPerByteInSeconds;
    for oConnection in oSelf.__aoConnectionsToProxyNotConnectedToAServer:
      oConnection.nSendDelayPerByteInSeconds = nSendDelayPerByteInSeconds;
    for oConnection in oSelf.__doSecureConnectionToServerThroughProxy_by_sbProtocolHostPort.values():
      oConnection.nSendDelayPerByteInSeconds = nSendDelayPerByteInSeconds;
    for oConnection in oSelf.__doExternalizedConnectionToServerThroughProxy_by_sbProtocolHostPort.values():
      oConnection.nSendDelayPerByteInSeconds = nSendDelayPerByteInSeconds;
  
  @ShowDebugOutput
  def fStop(oSelf):
    oSelf.__oPropertyAccessTransactionLock.fAcquire();
    try:
      if oSelf.bTerminated:
        return fShowDebugOutput("Already terminated.");
      if oSelf.__bStopping:
        return fShowDebugOutput("Already stopping.");
      fShowDebugOutput("Stopping...");
      oSelf.__bStopping = True;
      aoConnectionsThatCanBeStopped = oSelf.__faoGetAllNonExternalConnections();
    finally:
      oSelf.__oPropertyAccessTransactionLock.fRelease();
    fShowDebugOutput("Stopping connections to proxy server...");
    if len(aoConnectionsThatCanBeStopped) == 0:
      # We stopped when there were no connections: we are terminated.
      fShowDebugOutput("Terminated.");
      oSelf.__oTerminatedLock.fRelease();
      oSelf.fFireCallbacks("terminated");
    else:
      for oConnection in aoConnectionsThatCanBeStopped:
        oConnection.fStop();
  
  @ShowDebugOutput
  def fTerminate(oSelf):
    oSelf.__oPropertyAccessTransactionLock.fAcquire();
    try:
      # We'll run through all the steps no matter what.
      if oSelf.bTerminated:
        fShowDebugOutput("Already terminated.");
        return True;
      oSelf.__bStopping = True;
      aoConnectionsThatShouldBeTerminated = oSelf.__faoGetAllConnections();
    finally:
      oSelf.__oPropertyAccessTransactionLock.fRelease();
    if len(aoConnectionsThatShouldBeTerminated) == 0:
      # We terminated when there were no connections: we are terminated.
      fShowDebugOutput("Terminated.");
      oSelf.__oTerminatedLock.fRelease();
      oSelf.fFireCallbacks("terminated");
    else:
      for oConnection in aoConnectionsThatShouldBeTerminated:
        fShowDebugOutput("Terminating connection to proxy server %s..." % oConnection);
        oConnection.fTerminate();
  
  @ShowDebugOutput
  def fWait(oSelf):
    return oSelf.__oTerminatedLock.fWait();
  @ShowDebugOutput
  def fbWait(oSelf, nTimeoutInSeconds):
    return oSelf.__oTerminatedLock.fbWait(nTimeoutInSeconds);
  
  @ShowDebugOutput
  def fo0GetProxyServerURLForURL(oSelf, oURL):
    return oSelf.oProxyServerURL.foClone();
  
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
      fShowDebugOutput("Stopping.");
      return None;
    if not oURL.bSecure:
      o0Connection = oSelf.__fo0GetUnusedConnectionToProxyAndStartTransaction();
    else:
      o0Connection = oSelf.__fo0GetUnusedConnectionToServerThroughProxyAndStartTransaction(
        oURL.oBase,
        bSecure = True,
        bExternalize = False,
      );
    try:
      if oSelf.__bStopping:
        fShowDebugOutput("Stopping.");
        return None;
      assert o0Connection, \
          "Expected a connection but got %s" % repr(o0Connection);
      oResponse = o0Connection.foSendRequestAndReceiveResponse(
        oRequest,
        u0zMaxStatusLineSize = u0zMaxStatusLineSize,
        u0zMaxHeaderNameSize = u0zMaxHeaderNameSize,
        u0zMaxHeaderValueSize = u0zMaxHeaderValueSize,
        u0zMaxNumberOfHeaders = u0zMaxNumberOfHeaders,
        u0zMaxBodySize = u0zMaxBodySize,
        u0zMaxChunkSize = u0zMaxChunkSize,
        u0zMaxNumberOfChunks = u0zMaxNumberOfChunks,
        u0MaxNumberOfChunksBeforeDisconnecting = u0MaxNumberOfChunksBeforeDisconnecting,
      );
    finally:
      o0Connection.fEndTransaction();
    o0CookieStore = oSelf.o0CookieStore;
    if o0CookieStore: o0CookieStore.fUpdateFromResponseAndURL(oResponse, oURL);
    return oResponse;
  
  @ShowDebugOutput
  def fo0GetConnectionAndStartTransactionForURL(oSelf, oServerBaseURL, bSecure = True):
    if oSelf.__bStopping:
      fShowDebugOutput("Stopping.");
      return None;
    return oSelf.__fo0GetUnusedConnectionToServerThroughProxyAndStartTransaction(
      oServerBaseURL = oServerBaseURL,
      bSecure = bSecure,
      bExternalize = True,
    );
      
  @ShowDebugOutput
  def __fo0ReuseUnusedConnectionToProxyAndStartTransaction(oSelf):
    oSelf.__oPropertyAccessTransactionLock.fbAcquire();
    try:
      # Try to find the non-secure connection that is available:
      for oConnection in oSelf.__aoConnectionsToProxyNotConnectedToAServer:
        try: # Try to start a transaction; this will only succeed on an idle connection.
          oConnection.fStartTransaction(
            n0TimeoutInSeconds = oSelf.__n0TransactionTimeoutInSeconds,
          );
        except cTCPIPConnectionCannotBeUsedConcurrentlyException:
          pass; # The connection is already in use
        else:
          fShowDebugOutput("Reusing existing connection to proxy: %s" % repr(oConnection));
          return oConnection;
      return None;
    finally:
      oSelf.__oPropertyAccessTransactionLock.fRelease();
  
  @ShowDebugOutput
  def __fo0GetUnusedConnectionToProxyAndStartTransaction(oSelf):
    # Try to reuse a non-secure connection if possible:
    o0Connection = oSelf.__fo0ReuseUnusedConnectionToProxyAndStartTransaction();
    if o0Connection:
      fShowDebugOutput("Existing connectiong to proxy reused: %s." % repr(o0Connection));
      return o0Connection;
    # Try to create a new connection if possible:
    if (
      oSelf.__u0MaxNumberOfConnectionsToProxy is None
      or oSelf.__fuCountAllConnections() < oSelf.__u0MaxNumberOfConnectionsToProxy
    ):
      o0Connection = oSelf.__fo0CreateNewConnectionToProxyAndStartTransaction(
        n0zConnectTimeoutInSeconds = oSelf.__n0zConnectToProxyTimeoutInSeconds,
      );
      if oSelf.__bStopping:
        fShowDebugOutput("Stopping.");
        return None;
      assert o0Connection, \
          "Expected a connection but got %s" % o0Connection;
      fShowDebugOutput("New connection to proxy created: %s." % repr(o0Connection));
      return o0Connection;
    # Wait until we can start a transaction on any of the existing connections,
    # i.e. the conenction is idle:
    fShowDebugOutput("Maximum number of connections to proxy reached; waiting for a connection to become idle...");
    n0zConnectEndTime = (
      zNotProvided if not fbIsProvided(oSelf.__n0zConnectToProxyTimeoutInSeconds) else
      None if oSelf.__n0zConnectToProxyTimeoutInSeconds is None else
      time.time() + oSelf.__n0zConnectToProxyTimeoutInSeconds
    );
    # Since we want multiple thread to wait in turn, use a lock to allow only one
    # thread to enter the next block of code at a time.
    if not oSelf.__oWaitingForConnectionToBecomeAvailableLock.fbAcquire(oSelf.__nzConnectToProxyTimeoutInSeconds):
      # Another thread was waiting first and we timed out before a connection became available.
      raise cHTTPMaxConnectionsToServerReachedException(
        "Maximum number of connections to proxy reached.",
        dxDetails = {
          "bServerIsAProxy": True,
          "uMaxNumberOfConnections": oSelf.__u0MaxNumberOfConnectionsToProxy, # Cannot be None at this point
        },
      );
    try:
      # See if a transaction can be started on one or more of the existing connections:
      aoConnectionsWithStartedTransactions = cHTTPConnection.faoWaitUntilTransactionsCanBeStartedAndStartTransactions(
        aoConnections = oSelf.__faoGetAllNonExternalConnections(),
        n0WaitTimeoutInSeconds = 0,
      );
      if not aoConnectionsWithStartedTransactions:
        # We timed out before a connection became available.
        raise cHTTPMaxConnectionsToServerReachedException(
          "Maximum number of connections to proxy reached.",
          dxDetails = {
            "bServerIsAProxy": True,
            "uMaxNumberOfConnections": oSelf.__u0MaxNumberOfConnectionsToProxy, # Cannot be None at this point
          },
        );
      # If one of the available connections is a non-secure connection, reuse it:
      for oConnection in aoConnectionsWithStartedTransactions:
        if oConnection in oSelf.__aoConnectionsToProxyNotConnectedToAServer:
          # End the transactions that we started on all other connections.
          for oOtherConnection in aoConnectionsWithStartedTransactions:
            if oOtherConnection != oConnection:
              oOtherConnection.fEndTransaction();
          # return the connection that can be reused.
          return oConnection;
      # There are only secure connections; terminate the first one and end the transaction on the others.
      for oSecureConnection in aoConnectionsWithStartedTransactions:
        if oSecureConnection == aoConnectionsWithStartedTransactions[0]:
          oSecureConnection.fDisconnect();
        else:
          oSecureConnection.fEndTransaction();
      # Create a new connection
      o0Connection = oSelf.__fo0CreateNewConnectionToProxyAndStartTransaction(
        n0zConnectTimeoutInSeconds = (
          zNotProvided if fbIsProvided(n0zConnectEndTime) else
          None if n0zConnectEndTime is None else 
          n0zConnectEndTime - time.time()
        ),
      );
      if oSelf.__bStopping:
        fShowDebugOutput("Stopping.");
        return None;
      assert o0Connection, \
          "Expected a connection but got %s" % o0Connection;
      fShowDebugOutput("New connection to proxy created: %s." % repr(o0Connection));
      return oConnection;
    finally:
      oSelf.__oWaitingForConnectionToBecomeAvailableLock.fRelease();
  
  @ShowDebugOutput
  def __fo0CreateNewConnectionToProxyAndStartTransaction(oSelf,
    # The connect timeout can be less than oSelf.__n0zConnectTimeoutInSeconds 
    # because we may have already have to wait for another connection to be
    # closed if we had reached the maximum number of connections.
    n0zConnectTimeoutInSeconds, 
  ):
    # Create a new socket and return that.
    fShowDebugOutput("Connecting to %s..." % oSelf.oProxyServerURL);
    oConnection = cHTTPConnection.foConnectTo(
      sbHost = oSelf.oProxyServerURL.sbHost,
      uPortNumber = oSelf.oProxyServerURL.uPortNumber,
      n0zConnectTimeoutInSeconds = n0zConnectTimeoutInSeconds,
      o0SSLContext = oSelf.__o0ProxySSLContext,
      bzCheckHost = oSelf.__bzCheckProxyHost,
      n0zSecureTimeoutInSeconds = oSelf.__n0zSecureConnectionToProxyTimeoutInSeconds,
      nSendDelayPerByteInSeconds = oSelf.nSendDelayPerByteInSeconds,
      f0HostInvalidCallback = lambda sbHost: oSelf.fFireCallbacks(
        "proxy host invalid",
        oProxyServerURL = oSelf.oProxyServerURL,
      ),
      f0ResolvingHostnameCallback = lambda sbHostname: oSelf.fFireCallbacks(
        "resolving proxy hostname to ip address",
        oProxyServerURL = oSelf.oProxyServerURL,
      ),
      f0ResolvingHostnameFailedCallback = lambda sbHostname: oSelf.fFireCallbacks(
        "resolving proxy hostname to ip address failed",
        oProxyServerURL = oSelf.oProxyServerURL,
      ),
      f0HostnameResolvedToIPAddressCallback = lambda sbHostname, sbIPAddress, sCanonicalName: oSelf.fFireCallbacks(
        "resolved proxy hostname to ip address",
        oProxyServerURL = oSelf.oProxyServerURL,
        sbIPAddress = sbIPAddress,
        sCanonicalName = sCanonicalName,
      ),
      f0ConnectingToIPAddressCallback = lambda sbHost, sbIPAddress, uPortNumber: oSelf.fFireCallbacks(
        "connecting to proxy",
        oProxyServerURL = oSelf.oProxyServerURL,
        sbIPAddress = sbIPAddress,
        uPortNumber = uPortNumber,
      ),
      f0ConnectingToIPAddressFailedCallback = lambda oException, sbHost, sbIPAddress, uPortNumber: oSelf.fFireCallbacks(
        "connecting to proxy failed",
        oException = oException,
        oProxyServerURL = oSelf.oProxyServerURL,
        sbIPAddress = sbIPAddress,
        uPortNumber = uPortNumber,
      ),
      f0ConnectedToIPAddressCallback = lambda sbHost, sbIPAddress, uPortNumber, oConnection: oSelf.fFireCallbacks(
        "created connection to proxy",
        oProxyServerURL = oSelf.oProxyServerURL,
        sbIPAddress = sbIPAddress,
        uPortNumber = uPortNumber,
        oConnection = oConnection,
      ),
      f0SecuringConnectionCallback = lambda sbHost, sbIPAddress, uPortNumber, oConnection, oSSLContext: oSelf.fFireCallbacks(
        "securing connection to proxy",
        oProxyServerURL = oSelf.oProxyServerURL,
        sbHost = sbHost,
        sbIPAddress = sbIPAddress,
        uPortNumber = uPortNumber,
        oConnection = oConnection,
        oSSLContext = oSSLContext,
      ),
      f0SecuringConnectionFailedCallback = lambda oException, sbHost, sbIPAddress, uPortNumber, oConnection, oSSLContext: oSelf.fFireCallbacks(
        "securing connection to proxy failed",
        oProxyServerURL = oSelf.oProxyServerURL,
        sbHost = sbHost,
        sbIPAddress = sbIPAddress,
        uPortNumber = uPortNumber,
        oConnection = oConnection,
        oSSLContext = oSSLContext,
        oException = oException,
      ),
      f0ConnectionSecuredCallback = lambda sbHost, sbIPAddress, uPortNumber, oConnection, oSSLContext: oSelf.fFireCallbacks(
        "secured connection to proxy",
        oProxyServerURL = oSelf.oProxyServerURL,
        sbHost = sbHost,
        sbIPAddress = sbIPAddress,
        uPortNumber = uPortNumber,
        oConnection = oConnection,
        oSSLContext = oSSLContext,
      ),
    );
    oConnection.fStartTransaction(
      n0TimeoutInSeconds = oSelf.__n0TransactionTimeoutInSeconds,
    );
    oConnection.fAddCallbacks({
      "wrote bytes": lambda oConnection, sbBytes: oSelf.fFireCallbacks(
        "wrote bytes",
        oConnection = oConnection,
        sbBytes = sbBytes,
      ),
      "read bytes": lambda oConnection, sbBytes: oSelf.fFireCallbacks(
        "read bytes",
        oConnection = oConnection,
        sbBytes = sbBytes,
      ),
      "sending request to server": lambda oConnection, oRequest: oSelf.fFireCallbacks(
        "sending request to proxy",
        oProxyServerURL = oSelf.oProxyServerURL,
        oConnection = oConnection,
        oRequest = oRequest,
      ),
      "sending request to server failed": lambda oConnection, oRequest, oException: oSelf.fFireCallbacks(
        "sending request to proxy failed",
        oProxyServerURL = oSelf.oProxyServerURL,
        oConnection = oConnection,
        oRequest = oRequest,
        oException = oException,
      ),
      "sent request to server": lambda oConnection, oRequest: oSelf.fFireCallbacks(
        "sent request to proxy",
        oProxyServerURL = oSelf.oProxyServerURL,
        oConnection = oConnection,
        oRequest = oRequest,
      ),
      "receiving response from server": lambda oConnection, o0Request: oSelf.fFireCallbacks(
        "receiving response from proxy",
        oProxyServerURL = oSelf.oProxyServerURL,
        oConnection = oConnection,
        o0Request = o0Request,
      ),
      "receiving response from server failed": lambda oConnection, o0Request, oException: oSelf.fFireCallbacks(
        "receiving response from proxy failed",
        oProxyServerURL = oSelf.oProxyServerURL,
        oConnection = oConnection,
        o0Request = o0Request,
        oException = oException,
      ),
      "received response from server": lambda oConnection, o0Request, oResponse: oSelf.fFireCallbacks(
        "received response from proxy",
        oProxyServerURL = oSelf.oProxyServerURL,
        oConnection = oConnection,
        o0Request = o0Request,
        oResponse = oResponse,
      ),
      "terminated": oSelf.__fHandleTerminatedCallbackForConnection,
    });
    oSelf.__aoConnectionsToProxyNotConnectedToAServer.append(oConnection);
    return oConnection;
  
  def __fHandleTerminatedCallbackForConnection(oSelf, oConnection):
    oSelf.fFireCallbacks(
      "terminated connection to proxy",
      oConnection = oConnection,
      oProxyServerURL = oSelf.oProxyServerURL,
      sbIPAddress = oConnection.sbRemoteIPAddress,
      uPortNumber = oConnection.uRemotePortNumber,
    );
    oSelf.__oPropertyAccessTransactionLock.fAcquire();
    try:
      if oConnection in oSelf.__aoConnectionsToProxyNotConnectedToAServer:
        oSelf.__aoConnectionsToProxyNotConnectedToAServer.remove(oConnection);
      else:
        for sbProtocolHostPort in oSelf.__doSecureConnectionToServerThroughProxy_by_sbProtocolHostPort:
          if oSelf.__doSecureConnectionToServerThroughProxy_by_sbProtocolHostPort[sbProtocolHostPort] == oConnection:
            del oSelf.__doSecureConnectionToServerThroughProxy_by_sbProtocolHostPort[sbProtocolHostPort];
            break;
          if oSelf.__doExternalizedConnectionToServerThroughProxy_by_sbProtocolHostPort[sbProtocolHostPort] == oConnection:
            del oSelf.__doExterminalizedConnectionToServerThroughProxy_by_sbProtocolHostPort[sbProtocolHostPort];
            break;
        else:
          raise AssertionError("A connection was terminated that we did not know exists (%s)" % repr(oConnection));
      # Return if we are not stopping or if there are other connections open:
      if not oSelf.__bStopping:
        return;
      if oSelf.__aoConnectionsToProxyNotConnectedToAServer:
        return;
      if oSelf.__doSecureConnectionToServerThroughProxy_by_sbProtocolHostPort:
        return;
      if oSelf.__doExternalizedConnectionToServerThroughProxy_by_sbProtocolHostPort:
        return;
    finally:
      oSelf.__oPropertyAccessTransactionLock.fRelease();
    # We are stopping and the last connection just terminated: we are terminated.
    fShowDebugOutput("Terminated.");
    oSelf.__oTerminatedLock.fRelease();
    oSelf.fFireCallbacks("terminated");
  
  @ShowDebugOutput
  def __fo0GetUnusedConnectionToServerThroughProxyAndStartTransaction(oSelf, oServerBaseURL, bSecure, bExternalize):
    assert bExternalize or bSecure, \
        "We never expect to create a connection through the proxy for internal use that is not secure!";
    # See if we already have a secure connection to the server that is not in use and reuse that if we do:
    if bSecure:
      assert m0SSL, \
          "mSSL not available";
      o0SecureConnection = oSelf.__doSecureConnectionToServerThroughProxy_by_sbProtocolHostPort.get(oServerBaseURL.sbBase);
      if o0SecureConnection:
        o0SecureConnection.fStartTransaction(
          n0TimeoutInSeconds = oSelf.__n0TransactionTimeoutInSeconds,
        );
        fShowDebugOutput("Reusing existing connection");
        return o0SecureConnection;
    o0ConnectionToProxy = oSelf.__fo0GetUnusedConnectionToProxyAndStartTransaction();
    if oSelf.__bStopping:
      if o0ConnectionToProxy:
        o0ConnectionToProxy.fEndTransaction();
      fShowDebugOutput("Stopping.");
      return None;
    assert o0ConnectionToProxy, \
        "Expected a connection but got %s" % o0ConnectionToProxy;
    # We have a connection to the the proxy and we need to ask it pipe the connection to a server by
    # sending a CONNECT request:
    oConnectionToProxy = o0ConnectionToProxy;
    oConnectRequest = cHTTPRequest(
      sbURL = oServerBaseURL.sbAddress,
      sbzMethod = b"CONNECT",
      o0zHeaders = cHTTPHeaders.foFromDict({
        b"Host": oServerBaseURL.sbAddress,
        b"Connection": b"Keep-Alive",
      }),
    );
    oSelf.fFireCallbacks(
      "connecting to server through proxy",
      oProxyServerURL = oSelf.oProxyServerURL,
      oConnection = oConnectionToProxy,
      sbServerHost = oServerBaseURL.sbHost,
      uServerPortNumber = oServerBaseURL.uPortNumber,
    );
    oConnectResponse = oConnectionToProxy.foSendRequestAndReceiveResponse(oConnectRequest);
    # oConnectResponse can be None if we are stopping.
    if oSelf.__bStopping:
      fShowDebugOutput("Stopping.");
      return None;
    if oConnectResponse.uStatusCode != 200:
      oSelf.fFireCallbacks(
        "connecting to server through proxy failed",
        oProxyServerURL = oSelf.oProxyServerURL,
        oConnection = oConnectionToProxy,
        sbServerHost = oServerBaseURL.sbHost,
        uServerPortNumber = oServerBaseURL.uPortNumber,
        uStatusCode = oConnectResponse.uStatusCode,
      );
      # I am not entirely sure if we can trust the connection after this, so let's close it to prevent issues:
      oConnectionToProxy.fDisconnect();
      raise cHTTPClientFailedToConnectToServerThroughProxyException(
        "The proxy did not accept our CONNECT request.",
        {"oConnectRequest": oConnectRequest, "oConnectResponse": oConnectResponse},
      );
    oSelf.fFireCallbacks(
      "created connection to server through proxy",
      oProxyServerURL = oSelf.oProxyServerURL,
      oConnection = oConnectionToProxy,
      sbServerHost = oServerBaseURL.sbHost,
      uServerPortNumber = oServerBaseURL.uPortNumber,
    );
    oConnectionToServerThroughProxy = oConnectionToProxy
    oConnectionToServerThroughProxy.fAddCallback(
      "terminated",
      lambda oConnection: oSelf.fFireCallbacks(
        "terminated connection to server through proxy",
        oProxyServerURL = oSelf.oProxyServerURL,
        oConnection = oConnection,
        sbServerHost = oServerBaseURL.sbHost,
        uServerPortNumber = oServerBaseURL.uPortNumber,
      ),
    );
    # We've used some time to setup the connection; reset the transaction timeout
    oConnectionToServerThroughProxy.fRestartTransaction(
      n0TimeoutInSeconds = oSelf.__n0TransactionTimeoutInSeconds,
    );
    if bSecure:
      fShowDebugOutput("Starting SSL negotiation...");
      # Wrap the connection in SSL.
      assert oSelf.__o0CertificateStore, \
          "Cannot make secure requests without a certificate store";
      if oSelf.__bVerifyCertificates:
        oSSLContext = oSelf.__o0CertificateStore.foGetClientsideSSLContextForHost(
          oServerBaseURL.sbHost,
        );
      else:
        oSSLContext = oSelf.__o0CertificateStore.foGetClientsideSSLContextWithoutVerificationForHost(
          oServerBaseURL.sbHost,
        );
      oSelf.fFireCallbacks(
        "securing connection to server through proxy",
        oProxyServerURL = oSelf.oProxyServerURL,
        oConnection = oConnectionToProxy,
        sbServerHost = oServerBaseURL.sbHost,
        uServerPortNumber = oServerBaseURL.uPortNumber,
        oSSLContext = oSSLContext,
      );
      try:
        oConnectionToServerThroughProxy.fSecure(
          oSSLContext = oSSLContext,
          n0zTimeoutInSeconds = oSelf.__n0zSecureConnectionToServerTimeoutInSeconds,
          bzCheckHost = oSelf.__bzCheckHost if oSelf.__bVerifyCertificates else False,
        );
      except m0SSL.mExceptions.cSSLException as oException:
        oSelf.fFireCallbacks(
          "securing connection to server through proxy failed",
          oProxyServerURL = oSelf.oProxyServerURL,
          oConnection = oConnectionToProxy,
          sbServerHost = oServerBaseURL.sbHost,
          uServerPortNumber = oServerBaseURL.uPortNumber,
          oSSLContext = oSSLContext,
          oException = oException,
        );
        raise;
      oSelf.fFireCallbacks(
        "secured connection to server through proxy",
        oProxyServerURL = oSelf.oProxyServerURL,
        oConnection = oConnectionToServerThroughProxy,
        sbServerHost = oServerBaseURL.sbHost,
        uServerPortNumber = oServerBaseURL.uPortNumber,
        oSSLContext = oSSLContext,
      );
    # Remember that we now have this secure connection to the server
    oSelf.__aoConnectionsToProxyNotConnectedToAServer.remove(oConnectionToServerThroughProxy);
    if bExternalize:
      oSelf.__doExternalizedConnectionToServerThroughProxy_by_sbProtocolHostPort[oServerBaseURL.sbBase] = oConnectionToServerThroughProxy;
    else:
      oSelf.__doSecureConnectionToServerThroughProxy_by_sbProtocolHostPort[oServerBaseURL.sbBase] = oConnectionToServerThroughProxy;
    # and start using it...
    oConnectionToServerThroughProxy.fRestartTransaction(
      n0TimeoutInSeconds = oSelf.__n0TransactionTimeoutInSeconds
    );
    return oConnectionToServerThroughProxy;
  
  def fasGetDetails(oSelf):
    # This is done without a property lock, so race-conditions exist and it
    # approximates the real values.
    if oSelf.bTerminated:
      return ["terminated"];
    o0CookieStore = oSelf.o0CookieStore;
    return [s for s in [
      "server: %s" % str(oSelf.oProxyServerURL),
      "%d connections to proxy server" % len(oSelf.__aoConnectionsToProxyNotConnectedToAServer),
      "%d secure connections to server through proxy" % len(oSelf.__doSecureConnectionToServerThroughProxy_by_sbProtocolHostPort),
      "%d externalized connections to server through proxy" % len(oSelf.__doExternalizedConnectionToServerThroughProxy_by_sbProtocolHostPort),
      "stopping" if oSelf.__bStopping else None,
    ] if s] + (
      o0CookieStore.fasGetDetails() if o0CookieStore else []
    );
