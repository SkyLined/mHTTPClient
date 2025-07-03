try: # mDebugOutput use is Optional
  from mDebugOutput import ShowDebugOutput, fShowDebugOutput;
except ModuleNotFoundError as oException:
  if oException.args[0] != "No module named 'mDebugOutput'":
    raise;
  ShowDebugOutput = lambda fx: fx; # NOP
  fShowDebugOutput = lambda x, s0 = None: x; # NOP

from mMultiThreading import (
  cLock,
  cWithCallbacks
);
from mHTTPConnection import (
  cConnection,
  cConnectionsToServerPool,
);
from mHTTPProtocol import (
  cRequest,
  cHeaders,
);
from mNotProvided import (
  fbIsProvided,
  fxGetFirstProvidedValue,
  fxzGetFirstProvidedValueIfAny,
  zNotProvided,
);
try: # SSL support is optional.
  import mSSL as m0SSL;
except:
  m0SSL = None; # No SSL support

from .iClient import iClient;
from .mExceptions import (
  cClientFailedToConnectToServerThroughProxyException,
);

# To turn access to data store in multiple variables into a single transaction, we will create locks.
# These locks should only ever be locked for a short time; if it is locked for too long, it is considered a "deadlock"
# bug, where "too long" is defined by the following value:
gnDeadlockTimeoutInSeconds = 1; # We're not doing anything time consuming, so this should suffice.

class cClientUsingProxyServer(iClient, cWithCallbacks):
  # Some sane limitation on the number of connections to the proxy makes sense, to reduce the risk of a bug in the
  # code causing an excessive number of connections to be made:
  u0DefaultMaxNumberOfConnectionsToProxy = 10;
  # The following defaults can be used to override the defaults from the mHTTPConnection classes.
  # If they are set to `zNotProvided`, the defaults from the mHTTPConnection classes will be used.
  n0zDefaultConnectToProxyTimeoutInSeconds = zNotProvided;
  n0zDefaultSecureConnectionToProxyTimeoutInSeconds = zNotProvided;
  n0zDefaultSecureConnectionToServerTimeoutInSeconds = zNotProvided;
  # There is no default transaction timeout in the mHTTPConnection classes, so this cannot be zNotProvided.
  
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
    oSelf.__n0zTransactionTimeoutInSeconds = n0zTransactionTimeoutInSeconds;
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
    if oProxyServerURL.bSecure and oSelf.__o0CertificateStore:
      if oSelf.__bVerifyCertificates:
        o0SSLContext = oSelf.__o0CertificateStore.foGetClientsideSSLContextForHost(
          oProxyServerURL.sbHost,
        );
      else:
        o0SSLContext = oSelf.__o0CertificateStore.foGetClientsideSSLContextWithoutVerificationForHost(
          oProxyServerURL.sbHost,
        );
    else:
      # The URL may either be "http://" or we will not be able to create secure connections when asked.
      o0SSLContext = None;
    oSelf.__oConnectionsToProxyPool = cConnectionsToServerPool(
      oProxyServerURL,
      u0zMaxNumberOfConnectionsToServer = oSelf.__u0MaxNumberOfConnectionsToProxy,
      o0SSLContext = o0SSLContext,
      bzCheckHost = oSelf.__bzCheckProxyHost,
      nSendDelayPerByteInSeconds = nSendDelayPerByteInSeconds,
    );
    oSelf.__oConnectionsToProxyPool.fAddCallbacks({
      "server host invalid": lambda oConnectionsToProxyPool, *, sbHost, oException: oSelf.fFireCallbacks(
        "proxy host invalid",
        sbHost = sbHost,
        oException = oException,
      ),
      "resolving server hostname to ip address": lambda oConnectionsToProxyPool, *, sbHostname: oSelf.fFireCallbacks(
        "resolving proxy hostname to ip address",
        sbHostname = sbHostname,
      ),
      "resolving server hostname to ip address failed": lambda oConnectionsToProxyPool, *, sbHostname, oException: oSelf.fFireCallbacks(
        "resolving proxy hostname to ip address failed",
        sbHostname = sbHostname,
        oException = oException,
      ),
      "resolved server hostname to ip address": lambda oConnectionsToProxyPool, *, sbHostname, sbIPAddress, sCanonicalName: oSelf.fFireCallbacks(
        "resolved proxy hostname to ip address",
        sbHostname = sbHostname,
        sbIPAddress = sbIPAddress,
        sCanonicalName = sCanonicalName,
      ),
      "creating connection to server": lambda oConnectionsToProxyPool, *, sbHost, uPortNumber, sbIPAddress: oSelf.fFireCallbacks(
        "creating connection to proxy",
        sbHost = sbHost,
        uPortNumber = uPortNumber,
        sbIPAddress = sbIPAddress,
      ),
      "creating connection to server failed": lambda oConnectionsToProxyPool, *, sbHost, uPortNumber, sbIPAddress, oException: oSelf.fFireCallbacks(
        "creating connection to proxy failed",
        sbHost = sbHost,
        uPortNumber = uPortNumber,
        sbIPAddress = sbIPAddress,
        oException = oException,
      ),
      "created connection to server": lambda oConnectionsToProxyPool, *, sbHost, uPortNumber, sbIPAddress, oConnection: oSelf.fFireCallbacks(
        "created connection to proxy",
        sbHost = sbHost,
        uPortNumber = uPortNumber,
        sbIPAddress = sbIPAddress,
        oConnection = oConnection,
      ),
      "terminated connection to server": lambda oConnectionsToProxyPool, *, sbHost, uPortNumber, sbIPAddress, oConnection: oSelf.fFireCallbacks(
        "terminated connection to proxy",
        sbHost = sbHost,
        uPortNumber = uPortNumber,
        sbIPAddress = oConnection.sbRemoteIPAddress,
        oConnection = oConnection,
      ),
      "securing connection to server": lambda oConnectionsToProxyPool, *, sbHost, uPortNumber, sbIPAddress, oConnection, oSSLContext: oSelf.fFireCallbacks(
        "securing connection to proxy",
        sbHost = sbHost,
        uPortNumber = uPortNumber,
        sbIPAddress = sbIPAddress,
        oConnection = oConnection,
        oSSLContext = oSSLContext,
      ),
      "securing connection to server failed": lambda oConnectionsToProxyPool, *, sbHost, uPortNumber, sbIPAddress, oConnection, oSSLContext, oException: oSelf.fFireCallbacks(
        "securing connection to proxy failed",
        sbHost = sbHost,
        uPortNumber = uPortNumber,
        sbIPAddress = sbIPAddress,
        oConnection = oConnection,
        oSSLContext = oSSLContext,
        oException = oException,
      ),
      "secured connection to server": lambda oConnectionsToProxyPool, *, sbHost, uPortNumber, sbIPAddress, oConnection, oSSLContext: oSelf.fFireCallbacks(
        "secured connection to proxy",
        sbHost = sbHost,
        uPortNumber = uPortNumber,
        sbIPAddress = sbIPAddress,
        oConnection = oConnection,
        oSSLContext = oSSLContext,
      ),
      "read bytes": lambda oConnectionsToProxyPool, *, oConnection, sbBytes: oSelf.fFireCallbacks(
        "read bytes",
        oConnection = oConnection,
        sbBytes = sbBytes,
      ),
      "wrote bytes": lambda oConnectionsToProxyPool, *, oConnection, sbBytes: oSelf.fFireCallbacks(
        "wrote bytes",
        oConnection = oConnection,
        sbBytes = sbBytes,
      ),
      "sending request to server": lambda oConnectionsToProxyPool, *, oConnection, oRequest: oSelf.fFireCallbacks(
        "sending request to proxy",
        oConnection = oConnection,
        oRequest = oRequest,
      ),
      "sending request to server failed": lambda oConnectionsToProxyPool, *, oConnection, oRequest, oException: oSelf.fFireCallbacks(
        "sending request to proxy failed",
        oConnection = oConnection,
        oRequest = oRequest,
        oException = oException,
      ),
      "sent request to server": lambda oConnectionsToProxyPool, *, oConnection, oRequest: oSelf.fFireCallbacks(
        "sent request to proxy",
        oConnection = oConnection,
        oRequest = oRequest,
      ),
      "receiving response from server": lambda oConnectionsToProxyPool, *, oConnection, o0Request: oSelf.fFireCallbacks(
        "receiving response from proxy",
        oConnection = oConnection,
        o0Request = o0Request,
      ),
      "receiving response from server failed": lambda oConnectionsToProxyPool, *, oConnection, o0Request, oException: oSelf.fFireCallbacks(
        "receiving response from proxy failed",
        oConnection = oConnection,
        o0Request = o0Request,
        oException = oException,
      ),
      "received response from server": lambda oConnectionsToProxyPool, *, oConnection, o0Request, oResponse: oSelf.fFireCallbacks(
        "received response from proxy",
        oConnection = oConnection,
        o0Request = o0Request,
        oResponse = oResponse,
      ),
      "received out-of-band data from server": lambda oConnectionsToProxyPool, *, oConnection, sbOutOfBandData: oSelf.fFireCallbacks(
        "received out-of-band data from proxy",
        oConnection = oConnection,
        sbOutOfBandData = sbOutOfBandData,
      ),
      "terminated": lambda oConnectionsToProxyPool: (
          fShowDebugOutput("Terminated."),
          oSelf.__oTerminatedLock.fRelease(),
          oSelf.fFireCallbacks("terminated"),
      ),
    });

    oSelf.__oReservedConnectionsToServersThroughProxyPropertyLock = cLock(
      "%s.__oReservedConnectionsToServersThroughProxyPropertyLock" % oSelf.__class__.__name__,
    );
    oSelf.__aoReservedConnectionsToServersThroughProxy = [];
    
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
      
      "creating connection to proxy",
      "creating connection to proxy failed",
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
      
      "creating connection to server through proxy",
      "creating connection to server through proxy failed",
      "created connection to server through proxy",
      "terminated connection to server through proxy",
      
      "securing connection to server through proxy",
      "securing connection to server through proxy failed", 
      "secured connection to server through proxy",
      
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
    finally:
      oSelf.__oPropertyAccessTransactionLock.fRelease();
    fShowDebugOutput("Stopping connections to proxy server...");
    # Once the connections to server pool instance terminates,
    # we will terminate too.
    oSelf.__oConnectionsToProxyPool.fStop();
  
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
    return oSelf.oProxyServerURL.foClone(); # always the same.
  
  @ShowDebugOutput
  def fo0GetResponseForRequestAndURL(oSelf,
    oRequest,
    oURL,
    *,
    u0zMaxStartLineSize = zNotProvided,
    u0zMaxHeaderLineSize = zNotProvided,
    u0zMaxNumberOfHeaders = zNotProvided,
    u0zMaxBodySize = zNotProvided,
    u0zMaxChunkSize = zNotProvided,
    u0zMaxNumberOfChunks = zNotProvided,
    u0MaxNumberOfChunksBeforeDisconnecting = None, # disconnect and return response once this many chunks are received.
  ):
    if oSelf.__bStopping:
      fShowDebugOutput("Stopping.");
      return None;
    if oURL.bSecure:
      o0Connection = oSelf.fo0GetConnectionAndStartTransactionForURL(oURL);
      if o0Connection is None:
        assert oSelf.__bStopping, \
            "A connection to the proxy was not available even though we are not stopping!?";
        return None;
      oConnection = o0Connection;
      try:
        oResponse = oConnection.foSendRequestAndReceiveResponse(
          oRequest,
          u0zMaxStartLineSize = u0zMaxStartLineSize,
          u0zMaxHeaderLineSize = u0zMaxHeaderLineSize,
          u0zMaxNumberOfHeaders = u0zMaxNumberOfHeaders,
          u0zMaxBodySize = u0zMaxBodySize,
          u0zMaxChunkSize = u0zMaxChunkSize,
          u0zMaxNumberOfChunks = u0zMaxNumberOfChunks,
          u0MaxNumberOfChunksBeforeDisconnecting = u0MaxNumberOfChunksBeforeDisconnecting,
        );
      finally:
        # We do not (yet) reuse connections.
        oConnection.fDisconnect();
        oConnection.fEndTransaction();
    else:
      # Sending a non-secure request through a HTTP proxy is pretty similar to 
      # sending a normal request to a server, except that we need to provide the
      # absolute URL in the request header and we send all of them to the same
      # proxy server.
      oRequest.sbURL = oURL.sbAbsolute;
      o0Response = oSelf.__oConnectionsToProxyPool.fo0SendRequestAndReceiveResponse(
        oRequest,
        u0zMaxStartLineSize = u0zMaxStartLineSize,
        u0zMaxHeaderLineSize = u0zMaxHeaderLineSize,
        u0zMaxNumberOfHeaders = u0zMaxNumberOfHeaders,
        u0zMaxBodySize = u0zMaxBodySize,
        u0zMaxChunkSize = u0zMaxChunkSize,
        u0zMaxNumberOfChunks = u0zMaxNumberOfChunks,
        u0MaxNumberOfChunksBeforeDisconnecting = u0MaxNumberOfChunksBeforeDisconnecting,
      );
      if o0Response is None:
        assert oSelf.__bStopping, \
            "A response was not received even though we are not stopping!?";
        return None;
      oResponse = o0Response;
    o0CookieStore = oSelf.o0CookieStore;
    if o0CookieStore: o0CookieStore.fUpdateFromResponseAndURL(oResponse, oURL);
    return oResponse;
  
  

  @ShowDebugOutput
  def fo0GetConnectionAndStartTransactionForURL(oSelf,
    oURL,
    bSecureConnection = True,
  ):
    if oSelf.__bStopping:
      fShowDebugOutput(oSelf, "Stopping.");
      return None;
    o0ConnectionToProxy = oSelf.__oConnectionsToProxyPool.fo0GetConnectionAndStartTransactionBeforeSendingRequest();
    if o0ConnectionToProxy is None:
      assert oSelf.__bStopping, \
          "A new connection to the proxy was not established even though we are not stopping!?";
      return None;
    oConnectionToProxy = o0ConnectionToProxy;
    oConnectRequest = cRequest(
      sbURL = oURL.sbAddress,
      sbzMethod = b"CONNECT",
      o0zHeaders = cHeaders.foFromDict({
        b"Host": oURL.sbAddress,
        b"Connection": b"Keep-Alive",
      }),
    );
    oSelf.fFireCallbacks(
      "creating connection to server through proxy",
      oProxyServerURL = oSelf.oProxyServerURL,
      oConnection = oConnectionToProxy,
      sbServerHost = oURL.sbHost,
      uServerPortNumber = oURL.uPortNumber,
    );
    oConnectResponse = oConnectionToProxy.foSendRequestAndReceiveResponse(oConnectRequest);
    # oConnectResponse can be None if we are stopping.
    if oSelf.__bStopping:
      fShowDebugOutput("Stopping.");
      return None;
    if oConnectResponse.uStatusCode != 200:
      oSelf.fFireCallbacks(
        "creating connection to server through proxy failed",
        oProxyServerURL = oSelf.oProxyServerURL,
        oConnection = oConnectionToProxy,
        sbServerHost = oURL.sbHost,
        uServerPortNumber = oURL.uPortNumber,
        uStatusCode = oConnectResponse.uStatusCode,
      );
      # I am not entirely sure if we can trust the connection after this, so let's close it to prevent issues:
      oConnectionToProxy.fDisconnect();
      raise cClientFailedToConnectToServerThroughProxyException(
        "The proxy did not accept our CONNECT request.",
        dxDetails = {"oConnectRequest": oConnectRequest, "oConnectResponse": oConnectResponse},
      );
    oSelf.fFireCallbacks(
      "created connection to server through proxy",
      oProxyServerURL = oSelf.oProxyServerURL,
      oConnection = oConnectionToProxy,
      sbServerHost = oURL.sbHost,
      uServerPortNumber = oURL.uPortNumber,
    );
    oConnectionToServerThroughProxy = oConnectionToProxy
    oConnectionToServerThroughProxy.fAddCallback(
      "terminated",
      lambda oConnection: oSelf.__fHandleConnectionToServerThroughProxyDisconnected(oConnection, oURL),
    );
    # We've used some time to setup the connection; reset the transaction timeout
    oConnectionToServerThroughProxy.fRestartTransaction(
      n0TimeoutInSeconds = fxGetFirstProvidedValue(oSelf.__n0zTransactionTimeoutInSeconds, cConnection.n0DefaultTransactionTimeoutInSeconds),
    );
    if bSecureConnection:
      assert m0SSL, \
          "mSSL is not available";
      fShowDebugOutput("Starting SSL negotiation...");
      # Wrap the connection in SSL.
      assert oSelf.__o0CertificateStore, \
          "Cannot make secure requests without a certificate store";
      if oSelf.__bVerifyCertificates:
        oSSLContext = oSelf.__o0CertificateStore.foGetClientsideSSLContextForHost(
          oURL.sbHost,
        );
      else:
        oSSLContext = oSelf.__o0CertificateStore.foGetClientsideSSLContextWithoutVerificationForHost(
          oURL.sbHost,
        );
      oSelf.fFireCallbacks(
        "securing connection to server through proxy",
        oProxyServerURL = oSelf.oProxyServerURL,
        oConnection = oConnectionToProxy,
        sbServerHost = oURL.sbHost,
        uServerPortNumber = oURL.uPortNumber,
        oSSLContext = oSSLContext,
      );
      try:
        oConnectionToServerThroughProxy.fSecure(
          oSSLContext = oSSLContext,
          n0zTimeoutInSeconds = oSelf.__n0zSecureConnectionToServerTimeoutInSeconds,
          bzCheckHost = oSelf.__bzCheckHost if oSelf.__bVerifyCertificates else False,
        );
      except m0SSL.cSSLException as oException:
        oSelf.fFireCallbacks(
          "securing connection to server through proxy failed",
          oProxyServerURL = oSelf.oProxyServerURL,
          oConnection = oConnectionToProxy,
          sbServerHost = oURL.sbHost,
          uServerPortNumber = oURL.uPortNumber,
          oSSLContext = oSSLContext,
          oException = oException,
        );
        raise;
      oSelf.fFireCallbacks(
        "secured connection to server through proxy",
        oProxyServerURL = oSelf.oProxyServerURL,
        oConnection = oConnectionToServerThroughProxy,
        sbServerHost = oURL.sbHost,
        uServerPortNumber = oURL.uPortNumber,
        oSSLContext = oSSLContext,
      );
    # and start using it...
    oConnectionToServerThroughProxy.fRestartTransaction(
      n0TimeoutInSeconds = fxGetFirstProvidedValue(oSelf.__n0zTransactionTimeoutInSeconds, cConnection.n0DefaultTransactionTimeoutInSeconds),
    );
    return oConnectionToServerThroughProxy;
  
  def __fHandleConnectionToServerThroughProxyDisconnected(oSelf, oConnectionToServerThroughProxy, oServerBaseURL):
    oSelf.fFireCallbacks(
      "terminated connection to server through proxy",
      oProxyServerURL = oSelf.oProxyServerURL,
      oConnection = oConnectionToServerThroughProxy,
      sbServerHost = oServerBaseURL.sbHost,
      uServerPortNumber = oServerBaseURL.uPortNumber,
    ),
  
  def fasGetDetails(oSelf):
    # This is done without a property lock, so race-conditions exist and it
    # approximates the real values.
    if oSelf.bTerminated:
      return ["terminated"];
    o0CookieStore = oSelf.o0CookieStore;
    uReservedConnectionsCount = len(oSelf.__aoReservedConnectionsToServersThroughProxy);
    return [s for s in [
      "proxy: %s" % str(oSelf.oProxyServerURL),
      "%d reserved connections" % uReservedConnectionsCount,
    ] + oSelf.__oConnectionsToProxyPool.fasGetDetails() + [
      "stopping" if oSelf.__bStopping else None,
    ] if s] + (
      o0CookieStore.fasGetDetails() if o0CookieStore else []
    );
