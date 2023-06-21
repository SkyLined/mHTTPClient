import socket, threading;

from mConsole import oConsole;
from mHTTPConnection import cHTTPConnection;
from mHTTPConnection.mExceptions import \
    cHTTPInvalidMessageException, \
    cTCPIPDataTimeoutException, \
    cTCPIPDNSUnknownHostnameException, \
    cTCPIPInvalidAddressException, \
    cTCPIPConnectionDisconnectedException, \
    cTCPIPConnectionRefusedException, \
    cTCPIPConnectionShutdownException, \
    cTCPIPConnectTimeoutException;
from mHTTPProtocol import cURL;
from mMultiThreading import cThread;

COLOR_NORMAL =            0x0F07; # Light gray
COLOR_INFO =              0x0F0F; # Bright white
COLOR_OK =                0x0F0A; # Bright green
COLOR_ERROR =             0x0F0C; # Bright red
COLOR_WARNING =           0x0F0E; # Yellow

uServerPortNumber = 28080;
def foGetServerURL(sNote):
  global uServerPortNumber;
  uServerPortNumber += 1;
  return cURL.foFromBytesString(b"http://localhost:%d/%s" % (uServerPortNumber, sNote));

oTestURL = cURL.foFromBytesString(b"http://example.com/");
oSecureTestURL = cURL.foFromBytesString(b"https://example.com/");
oSecureRedirectURL = cURL.foFromBytesString(b"http://skylined.nl/");
oUnknownHostnameURL = cURL.foFromBytesString(b"http://does.not.exist.example.com/unknown-hostname");
oInvalidAddressURL = cURL.foFromBytesString(b"http://0.0.0.0/invalid-address");
oConnectionRefusedURL = foGetServerURL(b"refuse-connection");
oConnectTimeoutURL = foGetServerURL(b"connect-timeout");
oConnectionDisconnectedURL = foGetServerURL(b"disconnect");
oConnectionShutdownURL = foGetServerURL(b"shutdown");
oResponseTimeoutURL = foGetServerURL(b"response-timeout");
oInvalidHTTPMessageURL = foGetServerURL(b"send-invalid-response");

def fTestClient(
  oHTTPClient,
  oCertificateStore,
  nEndWaitTimeoutInSeconds,
):
  oServersShouldBeRunningLock = threading.Lock();
  oServersShouldBeRunningLock.acquire(); # Released once servers should stop runnning.
  ############################################
  oConsole.fOutput("\u2500\u2500\u2500\u2500 Making a first test request to %s " % oTestURL, sPadding = "\u2500");
  (oRequest, o0Response) = oHTTPClient.fto0GetRequestAndResponseForURL(oTestURL);
  assert o0Response, \
      "No response!?";
  oResponse = o0Response;
  assert oResponse.uStatusCode == 200, \
      "Response code == %d instead of 200!?" % oResponse.uStatusCode;
  oConsole.fOutput("  oRequest = %s" % oRequest.fsbSerialize());
  oConsole.fOutput("  oResponse = %s" % oResponse.fsbSerialize());
  ############################################
  oConsole.fOutput("\u2500\u2500\u2500\u2500 Making a second test request to %s " % oTestURL, sPadding = "\u2500");
  (oRequest, o0Response) = oHTTPClient.fto0GetRequestAndResponseForURL(oTestURL);
  assert o0Response, \
      "No response!?";
  oResponse = o0Response;
  assert oResponse.uStatusCode == 200, \
      "Response code == %d instead of 200!?" % oResponse.uStatusCode;
  oConsole.fOutput("  oRequest = %s" % oRequest);
  oConsole.fOutput("  oResponse = %s" % oResponse);
  ############################################
  if oHTTPClient.__class__.__name__ == "cHTTPClient": 
    # cHTTPClient specific checks
    asbConnectionPoolsProtocolHostPort = set(oHTTPClient._cHTTPClient__doConnectionsToServerPool_by_sbProtocolHostPort.keys());
    assert asbConnectionPoolsProtocolHostPort == set((oTestURL.sbBase,)), \
        "Expected a oHTTPClient instance to have one cConnectionsToServerPool instance for %s, but found %s" % \
        (oTestURL.sbBase, repr(asbConnectionPoolsProtocolHostPort));
    oConnectionsToServerPool = oHTTPClient._cHTTPClient__doConnectionsToServerPool_by_sbProtocolHostPort.get(oTestURL.sbBase);
    assert oConnectionsToServerPool, \
        "Expected a cConnectionsToServerPool instance for %s, but found none" % oTestURL;
    aoConnections = oConnectionsToServerPool._cHTTPConnectionsToServerPool__aoConnections;
    assert len(aoConnections) == 1, \
        "Expected a cConnectionsToServerPool instance with one connection for %s, but found %d connections" % \
        (oTestURL, len(aoConnections));
  if oHTTPClient.__class__.__name__ == "cHTTPClientUsingProxyServer": 
    # cHTTPClientUsingProxyServer specific checks
    aoConnectionsToProxyNotConnectedToAServer = oHTTPClient._cHTTPClientUsingProxyServer__aoConnectionsToProxyNotConnectedToAServer;
    assert len(aoConnectionsToProxyNotConnectedToAServer) == 1, \
        "Expected one connection to the proxy, but found %d connections" % len(aoConnectionsToProxyNotConnectedToAServer);
    doSecureConnectionToServerThroughProxy_by_sbProtocolHostPort = oHTTPClient._cHTTPClientUsingProxyServer__doSecureConnectionToServerThroughProxy_by_sbProtocolHostPort;
    asSecureConnectionTargets = list(doSecureConnectionToServerThroughProxy_by_sbProtocolHostPort.keys());
    assert len(asSecureConnectionTargets) == 0, \
        "Expected no secure connections, but found %s" % repr(asSecureConnectionTargets);

  # Wrapping SSL secured sockets in SSL is not currently supported, so the
  # client cannot secure a connection to a server over a secure connection to a
  # proxy.
  oProxyServerURLForSecureTestURL = oHTTPClient.fo0GetProxyServerURLForURL(oSecureTestURL);
  bUsingSecureProxy = oProxyServerURLForSecureTestURL and oProxyServerURLForSecureTestURL.bSecure;
  # If we are not using a proxy, or the URL for the proxy server is not secure,
  # we can test a secure connection to the server.
  if bUsingSecureProxy:
    # Maybe fix with https://stackoverflow.com/questions/4393086/https-proxy-tunneling-with-the-ssl-module ?
    oConsole.fOutput(COLOR_WARNING, "*** Cannot test a secure URL with a secure proxy!");
  else:
    oConsole.fOutput("\u2500\u2500\u2500\u2500 Making a first test request to %s " % oSecureTestURL, sPadding = "\u2500");
    (oRequest, o0Response) = oHTTPClient.fto0GetRequestAndResponseForURL(oSecureTestURL);
    assert o0Response, \
        "No response!?";
    oResponse = o0Response;
    oConsole.fOutput("  oRequest = %s" % oRequest);
    oConsole.fOutput("  oResponse = %s" % oResponse);
    oConsole.fOutput("\u2500\u2500\u2500\u2500 Making a second test request to %s " % oSecureTestURL, sPadding = "\u2500");
    (oRequest, o0Response) = oHTTPClient.fto0GetRequestAndResponseForURL(oSecureTestURL);
    assert o0Response, \
        "No response!?";
    oResponse = o0Response;
    oConsole.fOutput("  oRequest = %s" % oRequest);
    oConsole.fOutput("  oResponse = %s" % oResponse);
    if oHTTPClient.__class__.__name__ == "cHTTPClient": 
      # cHTTPClient specific checks
      asbConnectionPoolsProtocolHostPort = set(oHTTPClient._cHTTPClient__doConnectionsToServerPool_by_sbProtocolHostPort.keys());
      assert asbConnectionPoolsProtocolHostPort == set((oTestURL.sbBase, oSecureTestURL.sbBase)), \
          "Expected a oHTTPClient instance to have a cConnectionsToServerPool instance for %s and %s, but found %s" % \
          (oTestURL.sbBase, oSecureTestURL.sbBase, repr(asbConnectionPoolsProtocolHostPort));
      
      oConnectionsToServerPool = oHTTPClient._cHTTPClient__doConnectionsToServerPool_by_sbProtocolHostPort.get(oSecureTestURL.sbBase);
      assert oConnectionsToServerPool, \
          "Expected a cConnectionsToServerPool instance for %s, but found none" % oSecureTestURL;
      aoConnections = oConnectionsToServerPool._cHTTPConnectionsToServerPool__aoConnections;
      assert len(aoConnections) == 1, \
          "Expected a cConnectionsToServerPool instance with one connection for %s, but found %d connections" % \
          (oSecureTestURL, len(aoConnections));
    if oHTTPClient.__class__.__name__ == "cHTTPClientUsingProxyServer": 
      # cHTTPClientUsingProxyServer specific checks
      aoConnectionsToProxyNotConnectedToAServer = oHTTPClient._cHTTPClientUsingProxyServer__aoConnectionsToProxyNotConnectedToAServer;
      doSecureConnectionToServerThroughProxy_by_sbProtocolHostPort = oHTTPClient._cHTTPClientUsingProxyServer__doSecureConnectionToServerThroughProxy_by_sbProtocolHostPort;
      asbSecureConnectionTargets = list(doSecureConnectionToServerThroughProxy_by_sbProtocolHostPort.keys());
      bFoundUnexpectedNonSecureConnections = len(aoConnectionsToProxyNotConnectedToAServer) != 0;
      bFoundUnexpectedSecureConnections = set(asbSecureConnectionTargets) != set((oSecureTestURL.sbBase,));
      if bFoundUnexpectedNonSecureConnections or bFoundUnexpectedSecureConnections:
        if bFoundUnexpectedNonSecureConnections:
          print("The HTTP client has unexpected non-secure connections!");
        if bFoundUnexpectedSecureConnections:
          print("The HTTP client has unexpected secure connections!");
        print("Non-secure connections:");
        for oNonSecureConnection in aoConnectionsToProxyNotConnectedToAServer:
          print("* %s" % repr(oNonSecureConnection));
        print("Secure connections:");
        for (sbProtocolHostPort, oSecureConnection) in doSecureConnectionToServerThroughProxy_by_sbProtocolHostPort.items():
          print("* %S => %s" % (sbProtocolHostPort, repr(oSecureConnection)));
        raise AssertionError();
  
  ### CHECK IF FOLLOWING REDIRECTS WORKS #########################################
  oConsole.fOutput("\u2500\u2500\u2500\u2500 Making a test request to %s " % oSecureRedirectURL, sPadding = "\u2500");
  (oRequest, o0Response) = oHTTPClient.fto0GetRequestAndResponseForURL(oSecureRedirectURL);
  assert o0Response, \
      "No response!?";
  oResponse = o0Response;
  assert 300 <= oResponse.uStatusCode <= 399, \
      "Response code == %d instead of 3xx!?" % oResponse.uStatusCode;
  oConsole.fOutput("  oRequest = %s" % oRequest);
  oConsole.fOutput("  oResponse = %s" % oResponse);
  ############################################
  if bUsingSecureProxy:
    # Maybe fix with https://stackoverflow.com/questions/4393086/https-proxy-tunneling-with-the-ssl-module ?
    oConsole.fOutput(COLOR_WARNING, "*** Cannot test a redirect to a secure URL with a secure proxy!");
  else:
    oConsole.fOutput("\u2500\u2500\u2500\u2500 Making a test request to %s and follow a redirect " % oSecureRedirectURL, sPadding = "\u2500");
    (oRequest, o0Response) = oHTTPClient.fto0GetRequestAndResponseForURL(oSecureRedirectURL, uMaximumNumberOfRedirectsToFollow = 5);
    assert o0Response, \
        "No response!?";
    oResponse = o0Response;
    assert oResponse.uStatusCode == 200, \
        "Response code == %d instead of 200!?" % oResponse.uStatusCode;
    oConsole.fOutput("  oRequest = %s" % oRequest);
    oConsole.fOutput("  oResponse = %s" % oResponse);
  
  # Create a server on a socket but do not listen so connections are refused.
  oConnectionRefusedServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0);
  oConnectionRefusedServerSocket.bind((oConnectionRefusedURL.sbHostname, oConnectionRefusedURL.uPortNumber));

  # Create a server on a socket that immediately closes the connection.
  oConnectionDisconnectedServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0);
  oConnectionDisconnectedServerSocket.bind((oConnectionDisconnectedURL.sbHostname, oConnectionDisconnectedURL.uPortNumber));
  oConnectionDisconnectedServerSocket.listen(1);
  def fConnectionDisconnectedServerThread():
    (oClientSocket, (sClientIP, uClientPortNumber)) = oConnectionDisconnectedServerSocket.accept();
    oConsole.fOutput("Disconnect server is disconnecting the connection...");
    oClientSocket.close();
    oConsole.fOutput("Disconnect server thread terminated.");
    
  oConnectionDisconnectedServerThread = cThread(fConnectionDisconnectedServerThread);
  oConnectionDisconnectedServerThread.fStart(bVital = False);
  
  # Create a server on a socket that immediately shuts down the connection.
  oConnectionShutdownServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0);
  oConnectionShutdownServerSocket.bind((oConnectionShutdownURL.sbHostname, oConnectionShutdownURL.uPortNumber));
  oConnectionShutdownServerSocket.listen(1);
  def fConnectionShutdownServerThread():
    (oClientSocket, (sClientIP, uClientPortNumber)) = oConnectionShutdownServerSocket.accept();
    oConsole.fOutput("Shutdown server is shutting down the connection for writing...");
    oClientSocket.shutdown(socket.SHUT_WR);
    oConsole.fOutput("Shutdown server is sleeping to keep the connection open....");
    oServersShouldBeRunningLock.acquire();
    oServersShouldBeRunningLock.release();
    oConsole.fOutput("Shutdown server thread terminated.");
    
  oConnectionShutdownServerThread = cThread(fConnectionShutdownServerThread);
  oConnectionShutdownServerThread.fStart(bVital = False);

  # Create a server on a socket that does not send a response.
  oResponseTimeoutServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0);
  oResponseTimeoutServerSocket.bind((oResponseTimeoutURL.sbHostname, oResponseTimeoutURL.uPortNumber));
  oResponseTimeoutServerSocket.listen(1);
  def fResponseTimeoutServerThread():
    (oClientSocket, (sClientIP, uClientPortNumber)) = oResponseTimeoutServerSocket.accept();
    oConsole.fOutput("Response timeout server receiving request...");
    oClientSocket.recv(0x1000);
    oConsole.fOutput("Response timeout server is sleeping to avoid sending a response...");
    oServersShouldBeRunningLock.acquire();
    oServersShouldBeRunningLock.release();
    oConsole.fOutput("Response timeout thread terminated.");
    
  oResponseTimeoutServerThread = cThread(fResponseTimeoutServerThread);
  oResponseTimeoutServerThread.fStart(bVital = False);

  # Create a server on a socket that sends an invalid response.
  oInvalidHTTPMessageServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0);
  oInvalidHTTPMessageServerSocket.bind((oInvalidHTTPMessageURL.sbHostname, oInvalidHTTPMessageURL.uPortNumber));
  oInvalidHTTPMessageServerSocket.listen(1);
  sbInvalidResponse = b"Hello, world!\r\n";
  def fInvalidHTTPMessageServerThread():
    (oClientSocket, (sClientIP, uClientPortNumber)) = oInvalidHTTPMessageServerSocket.accept();
    oConsole.fOutput("Invalid HTTP Message server received request; sending invalid response...");
    oClientSocket.recv(0x1000); # This should cover the request, which we discard.
    oClientSocket.send(sbInvalidResponse);
    oConsole.fOutput("Invalid HTTP Message server thread terminated.");
  
  oInvalidHTTPMessageServerThread = cThread(fInvalidHTTPMessageServerThread);
  oInvalidHTTPMessageServerThread.fStart(bVital = False);
  
  for (uNumberOfRequests, oURL, cExpectedExceptionClass, acAcceptableExceptionClasses, auAcceptableStatusCodes) in (
    (1, oUnknownHostnameURL,
        cTCPIPDNSUnknownHostnameException, [],
        [400]),
    (1, oInvalidAddressURL,
        cTCPIPInvalidAddressException, [],
        [400]),
    (1, oConnectionRefusedURL,
        cTCPIPConnectionRefusedException, [cTCPIPConnectTimeoutException],
        [502]),
    (1, oConnectTimeoutURL,
        cTCPIPConnectTimeoutException, [],
        [502, 504]),
    (1, oConnectionDisconnectedURL,
        cTCPIPConnectionDisconnectedException, [cTCPIPConnectionShutdownException],
        [502]),
    (1, oConnectionShutdownURL,
        cTCPIPConnectionShutdownException, [],
        [502]),
    (1, oResponseTimeoutURL,
        cTCPIPDataTimeoutException, [],
        [504]),
    (1, oInvalidHTTPMessageURL,
        cHTTPInvalidMessageException, [],
        [502]),
  ):
    oConsole.fOutput("\u2500\u2500\u2500\u2500 Making a test request to %s " % oURL, sPadding = "\u2500");
    if oHTTPClient.__class__.__name__ == "cHTTPClient":
      oConsole.fStatus("  * Expecting %s exception..." % cExpectedExceptionClass.__name__);
      auAcceptableStatusCodes = None;
    if oHTTPClient.__class__.__name__ == "cHTTPClientUsingProxyServer":
      if auAcceptableStatusCodes:
        oConsole.fStatus("  * Expecting a HTTP %s reponse..." % "/".join(["%03d" % uStatusCode for uStatusCode in auAcceptableStatusCodes]));
        cExpectedExceptionClass = None;
    for uConnectionNumber in range(1, uNumberOfRequests + 1):
      if uConnectionNumber < uNumberOfRequests:
        # We do not yet expect an exception, so we won't handle one.
        o0Response = oHTTPClient.fo0GetResponseForURL(oURL);
        assert o0Response, \
            "No response!?";
        oResponse = o0Response;
        oConsole.fOutput("  oResponse = %s" % oResponse);
      else:
        try:
          # Use a short connect timeout to speed things up: all connections should be created in about 1 second except the
          # one that purposefully times out and this way we do not have to wait for that to happen very long.
          o0Response = oHTTPClient.fo0GetResponseForURL(oURL);
          assert o0Response, \
              "No response!?";
          oResponse = o0Response;
          if auAcceptableStatusCodes:
            assert oResponse.uStatusCode in auAcceptableStatusCodes, \
                "Expected a HTTP %s response, got %s" % \
                ("/".join(["%03d" % uStatusCode for uStatusCode in auAcceptableStatusCodes]), oResponse.fsGetStatusLine());
          oConsole.fOutput("  oResponse = %s" % oResponse);
        except Exception as oException:
          if oException.__class__ is cExpectedExceptionClass:
            oConsole.fOutput("  + Threw %s." % repr(oException));
          elif oException.__class__ in acAcceptableExceptionClasses:
            oConsole.fOutput(COLOR_WARNING, "  ~ Threw %s." % repr(oException));
            oConsole.fOutput("    Expected %s." % cExpectedExceptionClass.__name__);
          else:
            oConsole.fOutput(COLOR_ERROR, "  - Threw %s." % repr(oException));
            if cExpectedExceptionClass:
              oConsole.fOutput("    Expected %s." % cExpectedExceptionClass.__name__);
            else:
              oConsole.fOutput("    No exception expected.");
            raise;
        else:
          if cExpectedExceptionClass:
            oConsole.fOutput(COLOR_ERROR, "  - Expected %s." % cExpectedExceptionClass.__name__);
            raise AssertionError("No exception");
  
  # Allow server threads to stop.
  oServersShouldBeRunningLock.release();
  
  oConsole.fOutput("\u2500\u2500\u2500\u2500 Stopping HTTP Client ", sPadding = "\u2500");
  oHTTPClient.fStop();
  assert oHTTPClient.fbWait(nEndWaitTimeoutInSeconds), \
    "HTTP Client did not stop in time";
  
  oConsole.fOutput("\u2500\u2500\u2500\u2500 Stopping connection refused server ", sPadding = "\u2500");
  oConnectionRefusedServerSocket.close(); # Has no thread.

  oConsole.fOutput("\u2500\u2500\u2500\u2500 Stopping connection closed server ", sPadding = "\u2500");
  oConnectionDisconnectedServerSocket.close();
  assert oConnectionDisconnectedServerThread.fbWait(nEndWaitTimeoutInSeconds), \
      "Connection closed server thread (%d/0x%X) did not stop in time." % \
      (oConnectionDisconnectedServerThread.uId, oConnectionDisconnectedServerThread.uId);
  
  oConsole.fOutput("\u2500\u2500\u2500\u2500 Stopping connection shutdown server ", sPadding = "\u2500");
  oConnectionShutdownServerSocket.close();
  assert oConnectionShutdownServerThread.fbWait(nEndWaitTimeoutInSeconds), \
      "Connection shutdown server thread (%d/0x%X) did not stop in time." % \
      (oConnectionShutdownServerThread.uId, oConnectionShutdownServerThread.uId);
  
  oConsole.fOutput("\u2500\u2500\u2500\u2500 Stopping response timeout server ", sPadding = "\u2500");
  oResponseTimeoutServerSocket.close();
  assert oResponseTimeoutServerThread.fbWait(nEndWaitTimeoutInSeconds), \
      "Connection shutdown server thread (%d/0x%X) did not stop in time." % \
      (oResponseTimeoutServerThread.uId, oResponseTimeoutServerThread.uId);
  
  oConsole.fOutput("\u2500\u2500\u2500\u2500 Stopping invalid http message server ", sPadding = "\u2500");
  oInvalidHTTPMessageServerSocket.close();
  assert oInvalidHTTPMessageServerThread.fbWait(nEndWaitTimeoutInSeconds), \
      "Invalid http message server thread (%d/0x%X) did not stop in time." % \
      (oInvalidHTTPMessageServerThread.uId, oInvalidHTTPMessageServerThread.uId);
  
