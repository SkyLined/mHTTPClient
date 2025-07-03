from mConsole import oConsole;
from mHTTPClient import cClientUsingAutomaticProxyServer;

from fTestClient import fTestClient;

def fTestClientUsingAutomaticProxyServer(
  oCertificateStore,
  nEndWaitTimeoutInSeconds,
  f0LogEvents
):
  oConsole.fOutput("\u2500\u2500\u2500\u2500 Creating a cClientUsingAutomaticProxyServer instance... ", sPadding = "\u2500");
  oHTTPClient = cClientUsingAutomaticProxyServer(
    bVerifyCertificates = False,
    o0zCertificateStore = oCertificateStore,
    n0zConnectTimeoutInSeconds = 1, # Make sure connection attempts time out quickly to trigger a timeout exception.
  );
  if f0LogEvents: f0LogEvents(oHTTPClient, "oHTTPClient");
  for sEventName in oHTTPClient.fasGetEventNames():
    (lambda sEventName: oHTTPClient.fAddCallback(
      sEventName,
      lambda oHTTPClient, **dxArguments: oConsole.fOutput(
        "*** %s %s: %s" % (
          oHTTPClient,
          sEventName,
          ", ".join(
            "%s=%s" % (sArgumentName, str(xArgumentValue))
            for (sArgumentName, xArgumentValue) in dxArguments.items()
          )
        )
      ),
    ))(sEventName);
  
  oConsole.fOutput("\u2500\u2500\u2500\u2500 Running client tests through automatic proxy server... ", sPadding = "\u2500");
  fTestClient(oHTTPClient, oCertificateStore, nEndWaitTimeoutInSeconds);
  
  oConsole.fOutput("\u2500\u2500\u2500\u2500 Stopping cClientUsingAutomaticProxyServer instance... ", sPadding = "\u2500");
  oHTTPClient.fStop();
  assert oHTTPClient.fbWait(nEndWaitTimeoutInSeconds), \
      "cClientUsingAutomaticProxyServer instance did not stop in time";
