import os, sys, threading;
sModulePath = os.path.dirname(__file__);
sys.path = [sModulePath] + [sPath for sPath in sys.path if sPath.lower() != sModulePath.lower()];

from fTestDependencies import fTestDependencies;
fTestDependencies("--automatically-fix-dependencies" in sys.argv);
sys.argv = [s for s in sys.argv if s != "--automatically-fix-dependencies"];

try: # mDebugOutput use is Optional
  import mDebugOutput as m0DebugOutput;
except ModuleNotFoundError as oException:
  if oException.args[0] != "No module named 'mDebugOutput'":
    raise;
  m0DebugOutput = None;

guExitCodeInternalError = 1; # Use standard value;
try:
  try:
    from mConsole import oConsole;
  except:
    import sys, threading;
    oConsoleLock = threading.Lock();
    class oConsole(object):
      @staticmethod
      def fOutput(*txArguments, **dxArguments):
        sOutput = "";
        for x in txArguments:
          if isinstance(x, str):
            sOutput += x;
        sPadding = dxArguments.get("sPadding");
        if sPadding:
          sOutput.ljust(120, sPadding);
        oConsoleLock.acquire();
        print(sOutput);
        sys.stdout.flush();
        oConsoleLock.release();
      @staticmethod
      def fStatus(*txArguments, **dxArguments):
        pass;
  
  import os, sys;
  
  from mHTTPClient import cClient;
  from mHTTPProtocol import cURL;
  
  try:
    import mSSL as m0SSL;
  except ModuleNotFoundError as oException:
    if oException.args[0] != "No module named 'mSSL'":
      raise;
    m0SSL = None;
  
  HEADER = 0xFF0A;
  DELETE_FILE = 0xFF0C;
  DELETE_FOLDER = 0xFF04;
  OVERWRITE_FILE = 0xFF0E;
  
  def fShowDeleteOrOverwriteFileOrFolder(sFileOrFolderPath, bFile, s0NewContent):
    if not bFile:
      oConsole.fOutput(DELETE_FOLDER, " - ", sFileOrFolderPath);
    elif s0NewContent is None:
      oConsole.fOutput(DELETE_FILE, " - ", sFileOrFolderPath);
    else:
      oConsole.fOutput(OVERWRITE_FILE, " * ", sFileOrFolderPath, " => %d bytes." % len(s0NewContent));
  
  oEventLock = threading.Lock();
  def fLogEvents(oWithCallbacks, sWithCallbacks = None):
    def fAddCallback(sEventName):
      def fOutputEventDetails(oWithCallbacks, *txArguments, **dxArguments):
        oEventLock.acquire();
        try:
          oConsole.fOutput("┬─event: ", sWithCallbacks or str(oWithCallbacks), " => ", repr(sEventName));
          asArguments = [];
          for xValue in txArguments:
            asArguments.append(repr(xValue));
          for (sName, xValue) in dxArguments.items():
            asArguments.append(f"{repr(sName)} = {repr(xValue)}");
          for sArgument in asArguments[:-1]:
            oConsole.fOutput("├─", sArgument);
          for sArgument in asArguments[-1:]:
            oConsole.fOutput("└─", sArgument);
        finally:
          oEventLock.release();
      
      oWithCallbacks.fAddCallback(sEventName, fOutputEventDetails);
    
    for sEventName in oWithCallbacks.fasGetEventNames():
      fAddCallback(sEventName);
  
  bQuick = False;
  bTestClient = None;
  bTestClientUsingProxyServer = None;
  bTestClientUsingAutomaticProxyServer = False;
  f0LogEvents = None;
  # Enable/disable output for all classes
  for sArgument in sys.argv[1:]:
    if sArgument == "--quick": 
      bQuick = True;
    elif sArgument == "--full": 
      bTestClient = True;
      bTestClientUsingProxyServer = True;
      bTestClientUsingAutomaticProxyServer = True;
    elif sArgument in ["--events", "--log-events"]:
      f0LogEvents = fLogEvents;
    elif sArgument == "--debug":
      assert m0DebugOutput, \
          "m0DebugOutput module is not available";
      # Turn on debugging for various classes, including a few that are not directly exported.
      import mHTTPClient, mTCPIPConnection, mHTTPConnection, mHTTPProtocol;
      m0DebugOutput.fEnableDebugOutputForModule(mHTTPClient);
      m0DebugOutput.fEnableDebugOutputForModule(mHTTPConnection);
      m0DebugOutput.fEnableDebugOutputForModule(mTCPIPConnection);
      # Having everything from mHTTPProtocol output debug messages may be a bit too verbose, so
      # I've disabled output from the HTTP header classes to keep it reasonably clean.
      # m0DebugOutput.fEnableDebugOutputForClass(mHTTPProtocol.cHTTPHeader);
      # m0DebugOutput.fEnableDebugOutputForClass(mHTTPProtocol.cHTTPHeaders);
      m0DebugOutput.fEnableDebugOutputForClass(mHTTPProtocol.cRequest);
      m0DebugOutput.fEnableDebugOutputForClass(mHTTPProtocol.cResponse);
      m0DebugOutput.fEnableDebugOutputForClass(mHTTPProtocol.iMessage);
      if m0SSL is not None:
        m0DebugOutput.fEnableDebugOutputForModule(m0SSL);
      # Outputting debug information is slow, so increase the timeout!
      mHTTPClient.cClient.nDefaultConnectTimeoutInSeconds = 100;
      mHTTPClient.cClient.nDefaultTransactionTimeoutInSeconds = 100;
    else:
      # We assume this is a flag that enables a specific test. If this is the
      # first such flag, we will disable all tests to make sure we only run the
      # tests that are explicitly enabled.
      if bTestClient is None:
        bTestClient = False;
        bTestClientUsingProxyServer = False;
        bTestClientUsingAutomaticProxyServer = False;
      if sArgument == "--client":
        bTestClient = True;
      elif sArgument == "--proxy":
        bTestClientUsingProxyServer = True;
      elif sArgument == "--auto-proxy":
        bTestClientUsingAutomaticProxyServer = True;
      else:
        raise AssertionError("Unknown argument %s" % sArgument);
  
  nEndWaitTimeoutInSeconds = 10;
  sbTestHost = b"localhost";
  
  oLocalNonSecureURL = cURL.foFromBytesString(b"http://%s:28876/local-non-secure" % sbTestHost);
  oLocalSecureURL = cURL.foFromBytesString(b"https://%s:28876/local-secure" % sbTestHost);
  oProxyServerURL = cURL.foFromBytesString(b"https://%s:28876" % sbTestHost);
  oConsole.fOutput("\u2500\u2500\u2500\u2500 Creating a cCertificateStore instance ".ljust(160, "\u2500"));
  
  if m0SSL is not None:
    import tempfile;
    sCertificateAuthorityFolderPath = os.path.join(tempfile.gettempdir(), "tmp");
  
    oCertificateAuthority = m0SSL.cCertificateAuthority(sCertificateAuthorityFolderPath, "mHTTP Test");
    oConsole.fOutput("  oCertificateAuthority = ", str(oCertificateAuthority));
    if os.path.isdir(sCertificateAuthorityFolderPath):
      if bQuick:
        oConsole.fOutput(HEADER, "\u2500\u2500\u2500\u2500 Reset Certificate Authority folder... ", sPadding = "\u2500");
        oCertificateAuthority.fResetCacheFolder(fShowDeleteOrOverwriteFileOrFolder);
      else:
        oConsole.fOutput(HEADER, "\u2500\u2500\u2500\u2500 Delete Certificate Authority folder... ", sPadding = "\u2500");
        oCertificateAuthority.fDeleteCacheFolder(fShowDeleteOrOverwriteFileOrFolder);
    # Create a self-signed certificate for the test host.
    oCertificateAuthority.foGenerateServersideSSLContextForHost(sbTestHost);
    o0CertificateStore = m0SSL.cCertificateStore();
    o0CertificateStore.fAddCertificateAuthority(oCertificateAuthority);
    oConsole.fOutput("  o0CertificateStore = %s" % o0CertificateStore);
  else:
    o0CertificateStore = None;
  
  if bTestClient is not False:
    from fTestClient import fTestClient;
    oConsole.fOutput("\u2500\u2500\u2500\u2500 Creating a cClient instance ", sPadding = "\u2500");
    oClient = cClient(
      o0zCertificateStore = o0CertificateStore,
      n0zConnectTimeoutInSeconds = 1, # Make sure connection attempts time out quickly to trigger a timeout exception.
    );
    for sEventName in oClient.fasGetEventNames():
      (lambda sEventName: oClient.fAddCallback(
        sEventName,
        lambda oEventSource, **dxArguments: oConsole.fOutput(
          "*** %s %s: %s" % (
            oEventSource,
            sEventName,
            ", ".join(
              "%s=%s" % (sArgumentName, str(xArgumentValue))
              for (sArgumentName, xArgumentValue) in dxArguments.items()
            )
          )
        ),
      ))(sEventName);
    if f0LogEvents: f0LogEvents(oClient);
    oConsole.fOutput(HEADER, "\u2500\u2500\u2500\u2500 Test HTTP client ", sPadding = "\u2500");
    fTestClient(oClient, o0CertificateStore, nEndWaitTimeoutInSeconds);
  
  if bTestClientUsingProxyServer is not False:
    from fTestClientUsingProxyServer import fTestClientUsingProxyServer;
    oConsole.fOutput(HEADER, "\u2500\u2500\u2500\u2500 Test HTTP client and proxy server. ", sPadding = "\u2500");
    fTestClientUsingProxyServer(oProxyServerURL, o0CertificateStore, None, nEndWaitTimeoutInSeconds, f0LogEvents);
    if m0SSL:
      oConsole.fOutput(HEADER, "\u2500\u2500\u2500\u2500 Test HTTP client and proxy server with intercepted HTTPS connections ", sPadding = "\u2500");
      fTestClientUsingProxyServer(oProxyServerURL, o0CertificateStore, oCertificateAuthority, nEndWaitTimeoutInSeconds, f0LogEvents);
  
  if bTestClientUsingAutomaticProxyServer is not False:
    from fTestClientUsingAutomaticProxyServer import fTestClientUsingAutomaticProxyServer;
    oConsole.fOutput(HEADER, "\u2500\u2500\u2500\u2500 Test HTTP client with automatic proxy. ", sPadding = "\u2500");
    fTestClientUsingAutomaticProxyServer(o0CertificateStore, nEndWaitTimeoutInSeconds, f0LogEvents);
  
  if m0SSL is not None:
    if not bQuick:
      oConsole.fOutput(HEADER, "\u2500\u2500\u2500\u2500 Delete Certificate Authority folder... ", sPadding = "\u2500");
      oCertificateAuthority.fDeleteCacheFolder(fShowDeleteOrOverwriteFileOrFolder);
  
  oConsole.fOutput("+ Done.");
  
except Exception as oException:
  if m0DebugOutput:
    m0DebugOutput.fTerminateWithException(oException, guExitCodeInternalError, bShowStacksForAllThread = True);
  raise;
