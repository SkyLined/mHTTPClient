class cClientException(Exception):
  def __init__(oSelf, sMessage, *, o0Client = None, dxDetails = None):
    assert isinstance(dxDetails, dict), \
        "dxDetails must be a dict, not %s" % repr(dxDetails);
    oSelf.sMessage = sMessage;
    oSelf.o0Client = o0Client;
    oSelf.dxDetails = dxDetails;
    Exception.__init__(oSelf, sMessage, o0Client, dxDetails);
  
  def fasDetails(oSelf):
    return (
      (["Client: %s" % ", ".join(oSelf.o0Client.fasGetDetails())] if oSelf.o0Client else [])
      + ["%s: %s" % (str(sName), repr(xValue)) for (sName, xValue) in oSelf.dxDetails.items()]
    );
  def __str__(oSelf):
    return "%s (%s)" % (oSelf.sMessage, ", ".join(oSelf.fasDetails()));
  def __repr__(oSelf):
    return "<%s.%s %s>" % (oSelf.__class__.__module__, oSelf.__class__.__name__, oSelf);
  
class cClientFailedToConnectToServerThroughProxyException(cClientException):
  pass; # The proxy server did not respond to our CONNECT request with a 200 OK.

__all__ = [
  "cClientException",
  "cClientFailedToConnectToServerThroughProxyException",
];
