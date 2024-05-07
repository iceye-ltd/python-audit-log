import re
from dataclasses import dataclass
from urllib.parse import urlparse

from .schema import Principal, PrincipalType

MTLS_CERT_HEADER = "x-forwarded-client-cert"
SPIFFE_PATH_RE = re.compile(r"/ns/(?P<ns>[0-9a-z\-]+)/sa/(?P<sa>[0-9a-z\-]+)/?")
SUB_HEADER = "x-jwt-claim-sub"
ISS_HEADER = "x-jwt-claim-iss"
SUB_TYPE_HEADER = "x-jwt-claim-sub-type"


@dataclass
class ParsedSPIFFE:
    domain: str
    namespace: str
    service_account: str
    # SPIFFE ID parsed from header
    spiffe_id: str


def parse_spiffe(xfcc_header: str) -> ParsedSPIFFE:
    """Parse the X-Forwarded-Client-Cert header string and return the namespace, service account, and cluster internal hostname.

    Raises exception if header is invalid.

    Args:
        xfcc_header (str): X-Forwarded-Client-Cert header contents

    Returns:
        ParsedSPIFFE: Data parsed from SPIFFE header
    """
    try:
        # Split the header into a dictionary
        pairs = (pair.split("=") for pair in xfcc_header.split(";"))
        spiffe_dict = dict(pairs)
        # Only checking URI for now
        uri = spiffe_dict["URI"]
        parsed_uri = urlparse(uri)
        # Make sure it's a proper SPIFFE URI
        if parsed_uri.scheme.lower() != "spiffe":
            raise ValueError("URI scheme must be spiffe://")
        # Need to get namespace and service account from the URI
        parsed_path = SPIFFE_PATH_RE.search(parsed_uri.path)
        # Regex not matching would be returning `None`
        if not parsed_path:
            raise ValueError("Could not parse SPIFFE header")
        parsed_path_dict = parsed_path.groupdict()
        namespace = parsed_path_dict["ns"]
        service_account = parsed_path_dict["sa"]
    except (KeyError, ValueError) as e:
        raise ValueError("Invalid SPIFFE header") from e
    else:
        return ParsedSPIFFE(
            domain=parsed_uri.netloc,
            namespace=namespace,
            service_account=service_account,
            spiffe_id=uri,
        )


def get_principal_from_headers(
    headers: dict[str, str],
) -> Principal:
    """Get principal from headers, supports mTLS, headers set in Istio, and JWTs.

    Note: Do not use this to handle your auth, it expects auth to already be handled elsewhere and this is just to help get principals.

    Args:
        headers (dict[str, str]): Headers with all keys lowercase

    Raises:
        ValueError: Invalid configuration or headers
        KeyError: Missing headers that are required to be set

    Returns:
        dict[str, str]: Principal dictionary in proper format
    """
    if headers.get(MTLS_CERT_HEADER):
        spiffe = parse_spiffe(headers[MTLS_CERT_HEADER])
        return Principal(
            type=PrincipalType.SERVICE, authority=spiffe.domain, id=spiffe.spiffe_id
        )

    iss = headers[ISS_HEADER]
    sub = headers[SUB_HEADER]
    sub_type = headers[SUB_TYPE_HEADER]

    return Principal(type=PrincipalType(sub_type), authority=iss, id=sub)
