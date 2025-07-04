from mConsole import oConsole;

def ftxRequestHandler(
  oHTTPServer,
  oConnection,
  oRequest,
):
  oResponse = oConnection.foCreateResponses(
    uzStatusCode = 200,
    sb0Data = b"Hello, world!",
    bAddContentLengthHeader = True,
  );
  oResponse.fSetContentTypeHeader("text/plain");
  return (
    oResponse,
    None, # No next connection handler
  );

def fTestServer(
  cHTTPServer,
  cHTTPClient,
  oCertificateStore,
  oServerURL,
  nEndWaitTimeoutInSeconds,
  f0LogEvents,
):
  # Can be use to test cHTTPServer with a http:// or https:// URL.
  if oServerURL.bSecure:
    oConsole.fOutput("\u2500\u2500\u2500\u2500 Creating a cSSLContext instance for %s... " % repr(oServerURL.sbHostname), sPadding = "\u2500");
    o0SSLContext = oCertificateStore.foGetServersideSSLContextForHostname(oServerURL.sbHostname);
    oConsole.fOutput(0x0F0F, repr(oSSLContext._cSSLContext__oPythonSSLContext.get_ca_certs()));
    oConsole.fOutput("* oSSLContext for ", str(oServerURL.sbHostname, 'latin1'), ": ", str(o0SSLContext));
  else:
    o0SSLContext = None;
  oConsole.fOutput("\u2500\u2500\u2500\u2500 Creating a cHTTPServer instance at %s... " % oServerURL, sPadding = "\u2500");
  oHTTPServer = cHTTPServer(
    ftxRequestHandler,
    sbzHost = oServerURL.sbHostname,
    uzPortNumber = oServerURL.uPortNumber,
    o0SSLContext = o0SSLContext,
    bRaiseExceptionsInRequestHandler = True,
  );
  if f0LogEvents: f0LogEvents(oHTTPServer, "oHTTPServer");
  oConsole.fOutput("\u2500\u2500\u2500\u2500 Creating a new cHTTPClient instance... ", sPadding = "\u2500");
  oHTTPClient = cHTTPClient(oCertificateStore);
  if f0LogEvents: f0LogEvents(oHTTPClient, "oHTTPClient");
  oConsole.fOutput("\u2500\u2500\u2500\u2500 Making a first test request to %s... " % oServerURL, sPadding = "\u2500");
  o0Response = oHTTPClient.fo0GetResponseForURL(oServerURL);
  assert o0Response, \
      "No response!?";
  oConsole.fOutput(repr(o0Response.fsbSerialize()));
  oConsole.fOutput("\u2500\u2500\u2500\u2500 Making a second test request to %s... " % oServerURL, sPadding = "\u2500");
  o0Response = oHTTPClient.fo0GetResponseForURL(oServerURL);
  assert o0Response, \
      "No response!?";
  oConsole.fOutput(repr(o0Response.fsbSerialize()));
  oConsole.fOutput("\u2500\u2500\u2500\u2500 Stopping the cHTTPServer instance at %s... " % oServerURL, sPadding = "\u2500");
  oHTTPServer.fStop();
  assert oHTTPServer.fbWait(nEndWaitTimeoutInSeconds), \
      "cHTTPServer instance did not stop in time";
  oConsole.fOutput("\u2500\u2500\u2500\u2500 Stopping the cHTTPClient instance... ", sPadding = "\u2500");
  oHTTPClient.fStop();
  assert oHTTPClient.fbWait(nEndWaitTimeoutInSeconds), \
      "oHTTPClient instance did not stop in time";
