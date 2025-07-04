try: # mDebugOutput use is Optional
  from mDebugOutput import ShowDebugOutput, fShowDebugOutput;
except ModuleNotFoundError as oException:
  if oException.args[0] != "No module named 'mDebugOutput'":
    raise;
  ShowDebugOutput = lambda fx: fx; # NOP
  fShowDebugOutput = lambda x, s0 = None: x; # NOP

from mHTTPProtocol import (
  cHeaders,
  cInvalidURLException,
  cRequest,
  cURL,
);
from mMultiThreading import cWithCallbacks;
from mNotProvided import \
    fAssertTypes, \
    fbIsProvided, \
    zNotProvided;
try: # SSL support is optional.
  import mSSL as m0SSL;
except:
  m0SSL = None; # No SSL support


# To turn access to data store in multiple variables into a single transaction, we will create locks.
# These locks should only ever be locked for a short time; if it is locked for too long, it is considered a "deadlock"
# bug, where "too long" is defined by the following value:
gnDeadlockTimeoutInSeconds = 1; # We're not doing anything time consuming, so this should suffice.

class iClient(cWithCallbacks):
  bSSLIsSupported = m0SSL is not None;
  u0DefaultMaxNumberOfConnectionsToServer = 10;
  n0zDefaultConnectTimeoutInSeconds = 10;
  n0zDefaultSecureTimeoutInSeconds = 5;
  n0zDefaultTransactionTimeoutInSeconds = 10;
  
  def __init__(oSelf,
    *,
    o0CookieStore = None,
  ):
    oSelf.o0CookieStore = o0CookieStore;
  
  @property
  def bTerminated(oSelf):
    raise NotImplementedError("bTerminated has not been implemented!");
  # Check to make sure the connections to server pool is terminated before being discarded.
  def __del__(oSelf):
    assert oSelf.bTerminated, \
        "%s was not terminated before being deleted!" % oSelf;
  
  @staticmethod
  def foURLFromString(sURL):
    return cURL.foFromBytesString(bytes(sURL, "ascii", "strict"));
  @staticmethod
  def foURLFromBytesString(sbURL):
    return cURL.foFromBytesString(sbURL);
  
  @property
  def bStopping(oSelf):
    raise NotImplementedError();
  
  def fo0GetProxyServerURLForURL(oSelf):
    raise NotImplementedError();
  
  @ShowDebugOutput
  def fo0GetResponseForURL(oSelf,
    oURL,
    *,
    sbzMethod = zNotProvided,
    sbzVersion = zNotProvided,
    o0zHeaders = zNotProvided,
    sbBody = b"",
    bSetContentLengthHeader = False,
    u0zMaxStartLineSize = zNotProvided,
    u0zMaxHeaderLineSize = zNotProvided,
    u0zMaxNumberOfHeaders = zNotProvided,
    u0zMaxBodySize = zNotProvided,
    u0zMaxChunkSize = zNotProvided,
    u0zMaxNumberOfChunks = zNotProvided,
    u0MaxNumberOfChunksBeforeDisconnecting = None, # disconnect and return response once this many chunks are received.
    uMaximumNumberOfRedirectsToFollow = 0,
    bChangeMethodToGetAfterRedirect = True, # When the spec doesn't specify, you can choose what you want to happen.
  ):
    (o0OriginalRequest, o0Response) = oSelf.fto0GetRequestAndResponseForURL(
      oURL,
      sbzMethod = sbzMethod,
      sbzVersion = sbzVersion,
      o0zHeaders = o0zHeaders,
      sbBody = sbBody,
      bSetContentLengthHeader = bSetContentLengthHeader,
      u0zMaxStartLineSize = u0zMaxStartLineSize,
      u0zMaxHeaderLineSize = u0zMaxHeaderLineSize,
      u0zMaxNumberOfHeaders = u0zMaxNumberOfHeaders,
      u0zMaxBodySize = u0zMaxBodySize,
      u0zMaxChunkSize = u0zMaxChunkSize,
      u0zMaxNumberOfChunks = u0zMaxNumberOfChunks,
      u0MaxNumberOfChunksBeforeDisconnecting = u0MaxNumberOfChunksBeforeDisconnecting,
      uMaximumNumberOfRedirectsToFollow = uMaximumNumberOfRedirectsToFollow,
      bChangeMethodToGetAfterRedirect = bChangeMethodToGetAfterRedirect,
    );
    return o0Response;
  
  def fo0GetConnectionAndStartTransactionForURL(oSelf, oURL, bSecure = True):
    raise NotImplementedError();
  
  @ShowDebugOutput
  def fto0GetRequestAndResponseForURL(oSelf,
    oURL,
    *,
    sbzMethod = zNotProvided,
    sbzVersion = zNotProvided,
    o0zHeaders = zNotProvided,
    sbBody = b"",
    bSetContentLengthHeader = False,
    u0zMaxStartLineSize = zNotProvided,
    u0zMaxHeaderLineSize = zNotProvided,
    u0zMaxNumberOfHeaders = zNotProvided,
    u0zMaxBodySize = zNotProvided,
    u0zMaxChunkSize = zNotProvided,
    u0zMaxNumberOfChunks = zNotProvided,
    u0MaxNumberOfChunksBeforeDisconnecting = None, # disconnect and return response once this many chunks are received.
    uMaximumNumberOfRedirectsToFollow = 0,
    bChangeMethodToGetAfterRedirect = True, # When the spec doesn't specify, you can choose what you want to happen.
  ):
    fAssertTypes({
      "oURL": (oURL, cURL),
      "sbzMethod": (sbzMethod, bytes, zNotProvided),
      "sbzVersion": (sbzVersion, bytes, zNotProvided),
      "o0zHeaders": (o0zHeaders, cHeaders, None, zNotProvided),
      "sbBody": (sbBody, bytes),
      "bSetContentLengthHeader": (bSetContentLengthHeader, bool),
      "u0zMaxStartLineSize": (u0zMaxStartLineSize, int, None, zNotProvided),
      "u0zMaxHeaderLineSize": (u0zMaxHeaderLineSize, int, None, zNotProvided),
      "u0zMaxNumberOfHeaders": (u0zMaxNumberOfHeaders, int, None, zNotProvided),
      "u0zMaxBodySize": (u0zMaxBodySize, int, None, zNotProvided),
      "u0zMaxChunkSize": (u0zMaxChunkSize, int, None, zNotProvided),
      "u0zMaxNumberOfChunks": (u0zMaxNumberOfChunks, int, None, zNotProvided),
      "u0MaxNumberOfChunksBeforeDisconnecting": (u0MaxNumberOfChunksBeforeDisconnecting, int, None),
      "uMaximumNumberOfRedirectsToFollow": (uMaximumNumberOfRedirectsToFollow, int),
      "bChangeMethodToGetAfterRedirect": (bChangeMethodToGetAfterRedirect, bool),
    });
    o0OriginalRequest = None;
    auStatusCodesThatChangeMethodToGetAfterRedirect = (
      [301, 302, 303] if bChangeMethodToGetAfterRedirect else
      [303]
    );
    while True:
      if oSelf.bStopping:
        fShowDebugOutput("Stopping.");
        return (o0OriginalRequest, None);
      oRequest = oSelf.foGetRequestForURL(
        oURL,
        sbzMethod = sbzMethod,
        sbzVersion = sbzVersion,
        o0zHeaders = o0zHeaders,
        sbBody = sbBody,
        bSetContentLengthHeader = bSetContentLengthHeader,
      );
      if o0OriginalRequest is None:
        o0OriginalRequest = oRequest;
      o0Response = oSelf.fo0GetResponseForRequestAndURL(
        oRequest,
        oURL,
        u0zMaxStartLineSize = u0zMaxStartLineSize,
        u0zMaxHeaderLineSize = u0zMaxHeaderLineSize,
        u0zMaxNumberOfHeaders = u0zMaxNumberOfHeaders,
        u0zMaxBodySize = u0zMaxBodySize,
        u0zMaxChunkSize = u0zMaxChunkSize,
        u0zMaxNumberOfChunks = u0zMaxNumberOfChunks,
        u0MaxNumberOfChunksBeforeDisconnecting = u0MaxNumberOfChunksBeforeDisconnecting,
      );
      if oSelf.bStopping:
        fShowDebugOutput("Stopping.");
        return (o0OriginalRequest, None);
      assert o0Response, \
          "Expected a response but got %s" % repr(o0Response);
      oResponse = o0Response;
      # If we do not follow (any more) redirects, we are done.
      if uMaximumNumberOfRedirectsToFollow == 0:
        break;
      # If it's not a redirect, we are done.
      if 300 > oResponse.uStatusCode or oResponse.uStatusCode > 399:
        break;
      # If the redirect has no `Location` header, we are done.
      aoLocationHeaders = o0Response.oHeaders.faoGetForNormalizedName(b"Location");
      if len(aoLocationHeaders) == 0:
        break;
      # If there are multiple location headers, use the last one:
      oLocationHeader = aoLocationHeaders[-1];
      # If the redirect is relative, figure out the absolute URL to redirect to.
      # If the redirect is absolute, make sure it start with `http://` or `https://`.
      # If it does not, we are done. If the provided URL is invalid, we are done too.
      sbRedirectToURL = oLocationHeader.sbValue;
      asbRedirectToURL = sbRedirectToURL.split(b"://", 1);
      try:
        if len(asbRedirectToURL) == 1: # one element for relative URLs
          oURL = oURL.foFromRelativeBytesString(sbRedirectToURL);
        elif asbRedirectToURL[0] in [b"http", b"https"]: # two elements, first is protocol name for absolute URLs.
          oURL = cURL.foFromBytesString(sbRedirectToURL);
        else:
          break;
      except cInvalidURLException:
        break;
      uMaximumNumberOfRedirectsToFollow -= 1;
      # 303 always changes the method for the next request to GET. This behavior is undefined
      # for 301 and 302 in the specification, so the user gets to pick what they want to happen
      # using the bChangeMethodToGetAfterRedirect argument.
      # See https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections
      if (
        sbzMethod != b"GET" and
        oResponse.uStatusCode in auStatusCodesThatChangeMethodToGetAfterRedirect
      ):
        sbzMethod = b"GET";
        sbBody = b"";
        bSetContentLengthHeader = False;
      # Make another request to follow the redirect.
    return (o0OriginalRequest, o0Response);
  
  @ShowDebugOutput
  def foGetRequestForURL(oSelf,
    oURL,
    *,
    sbzMethod = zNotProvided,
    sbzVersion = zNotProvided,
    o0zHeaders = zNotProvided,
    sbBody = None,
    bSetContentLengthHeader = False,
  ):
    fAssertTypes({
      "oURL": (oURL, cURL),
      "sbzMethod": (sbzMethod, bytes, zNotProvided),
      "sbzVersion": (sbzVersion, bytes, zNotProvided),
      "o0zHeaders": (o0zHeaders, cHeaders, None, zNotProvided),
      "sbBody": (sbBody, bytes, None),
    });
    o0ProxyServerURL = oSelf.fo0GetProxyServerURLForURL(oURL);
    if oSelf.bStopping:
      fShowDebugOutput("Stopping.");
      return None;
    if o0ProxyServerURL is not None and fbIsProvided(o0zHeaders) and o0zHeaders is not None:
      oHeaders = o0zHeaders;
      for sbName in [b"Proxy-Authenticate", b"Proxy-Authorization", b"Proxy-Connection"]:
        assert len(oHeaders.faoGetForNormalizedName(sbName)) == 0, \
            "%s header is not implemented!" % repr(sbName);
    oRequest = cRequest(
      # When sending requests to a proxy, secure requests are forwarded directly to the server (after an initial
      # CONNECT request), so the URL in the request must be relative. Non-secure requests are made to the proxy,
      # which most have the absolute URL.
      sbURL = oURL.sbRelative if o0ProxyServerURL is None or oURL.bSecure else oURL.sbAbsolute,
      sbzMethod = sbzMethod,
      sbzVersion = sbzVersion,
      o0zHeaders = o0zHeaders,
      sbBody = sbBody,
    );
    if not oRequest.oHeaders.fbHasValueForNormalizedName(b"Host"):
      oRequest.oHeaders.foAddNameAndValue(b"Host", oURL.sbHostAndOptionalPort);
    if not oRequest.oHeaders.fbHasValueForNormalizedName(b"Accept-Encoding"):
      oRequest.oHeaders.foAddNameAndValue(b"Accept-Encoding", b", ".join(oRequest.asbSupportedCompressionTypes));
    o0CookieStore = oSelf.o0CookieStore;
    if o0CookieStore: o0CookieStore.fApplyToRequestForURL(oRequest, oURL);
    return oRequest;
  
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
    raise NotImplementedError();
  
  def fasGetDetails(oSelf):
    o0CookieStore = oSelf.o0CookieStore;
    return o0CookieStore.fasGetDetails() if o0CookieStore else [];
  
  def __repr__(oSelf):
    sModuleName = ".".join(oSelf.__class__.__module__.split(".")[:-1]);
    return "<%s.%s#%X|%s>" % (sModuleName, oSelf.__class__.__name__, id(oSelf), "|".join(oSelf.fasGetDetails()));
  
  def __str__(oSelf):
    return "%s#%X{%s}" % (oSelf.__class__.__name__, id(oSelf), ", ".join(oSelf.fasGetDetails()));
