from mHTTPClient import cClientUsingProxyServer;
from mHTTPProxy import cClientSideProxyServer;
from mConsole import oConsole;
from fTestClient import fTestClient;

def fTestClientUsingProxyServer(
  oProxyServerURL,
  oCertificateStore,
  oInterceptSSLConnectionsCertificateAuthority,
  nEndWaitTimeoutInSeconds,
  f0LogEvents
):
  oConsole.fOutput("\u2500\u2500\u2500\u2500 Creating a cClientSideProxyServer instance... ", sPadding = "\u2500");
  oProxyServer = cClientSideProxyServer(
    sbzHost = oProxyServerURL.sbHost,
    uzPortNumber = oProxyServerURL.uPortNumber,
    o0ServerSSLContext = (
      oCertificateStore.foGetServersideSSLContextForHost(oProxyServerURL.sbHost)
    ) if oProxyServerURL.bSecure else None,
    o0zCertificateStore = oCertificateStore,
    o0InterceptSSLConnectionsCertificateAuthority = oInterceptSSLConnectionsCertificateAuthority,
    # Make sure the proxy server times out waiting for the HTTP server
    # before the client times out waiting for the proxy.
    n0zConnectTimeoutInSeconds = 5,
    n0zTransactionTimeoutInSeconds = 6,
  );
  if f0LogEvents: f0LogEvents(oProxyServer, "oProxyServer");
  oConsole.fOutput("  oProxyServer = ", str(oProxyServer));
  oConsole.fOutput("\u2500\u2500\u2500\u2500 Creating a cClientUsingProxyServer instance... ", sPadding = "\u2500");
  oHTTPClient = cClientUsingProxyServer(
    oProxyServerURL = oProxyServerURL,
    bVerifyCertificates = False,
    o0zCertificateStore = oCertificateStore,
    n0zConnectToProxyTimeoutInSeconds = 1, # Make sure connection attempts time out quickly to trigger a timeout exception.
  );
  if f0LogEvents: f0LogEvents(oHTTPClient, "oHTTPClient");
  
  oConsole.fOutput("\u2500\u2500\u2500\u2500 Running client tests through proxy server... ", sPadding = "\u2500");
  fTestClient(oHTTPClient, oCertificateStore, nEndWaitTimeoutInSeconds);
  
  oConsole.fOutput("\u2500\u2500\u2500\u2500 Stopping cClientUsingProxyServer instance... ", sPadding = "\u2500");
  oHTTPClient.fStop();
  assert oHTTPClient.fbWait(nEndWaitTimeoutInSeconds), \
      "cClientUsingProxyServer instance did not stop in time";
  
  oConsole.fOutput("\u2500\u2500\u2500\u2500 Stopping cClientSideProxyServer instance... ", sPadding = "\u2500");
  oProxyServer.fStop();
  assert oProxyServer.fbWait(nEndWaitTimeoutInSeconds), \
      "cClientSideProxyServer instance did not stop in time";
  