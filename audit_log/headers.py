import re
from dataclasses import dataclass
from urllib.parse import urlparse

from joserfc import jwt
from joserfc.jwk import KeyFlexible

from .schema import PrincipalType

SPIFFE_PATH_RE = re.compile(r"/ns/(?P<ns>[0-9a-z\-]+)/sa/(?P<sa>[0-9a-z\-]+)/?")
CLAIMS_REQUESTS = jwt.JWTClaimsRegistry(
    iss={"essential": True},
    sub={"essential": True},
    sub_type={"essential": True, "values": ["USER", "SYSTEM"]},
)
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
    *,
    use_jwt: bool = False,
    jwt_key: KeyFlexible | None = None,
) -> dict[str, str]:
    """Get principal from headers, supports mTLS, headers set in Istio, and JWTs.

    Note: Do not use this to handle your auth, it expects auth to already be handled elsewhere and this is just to help get principals.

    Args:
        headers (dict[str, str]): Headers with all keys lowercase
        use_jwt (bool, optional): Enables checking of JWT for claims, requires `jwt_key` to be set (see joserfc documentation). Defaults to False.
        jwt_key (KeyFlexible | None, optional): Only required when `use_jwt` is True.

    Raises:
        ValueError: Invalid configuration or headers
        KeyError: Missing headers that are required to be set

    Returns:
        dict[str, str]: Principal dictionary in proper format
    """
    if (use_jwt and not headers.get("authorization")) or not headers.get(ISS_HEADER):
        spiffe = parse_spiffe(headers["x-forwarded-client-cert"])
        return {
            "type": PrincipalType.SERVICE,
            "authority": spiffe.domain,
            "id": spiffe.spiffe_id,
        }
    if use_jwt:
        if not jwt_key:
            raise ValueError("Missing jwt_key when use_jwt is enabled")
        raw_token = headers["authorization"].split(" ")[1]
        # Note: not validating the token here, expecting validation to be handled elsewhere
        token = jwt.decode(raw_token, jwt_key)
        CLAIMS_REQUESTS.validate(token.claims)
        iss = token.claims["iss"]
        sub = token.claims["sub"]
        sub_type = token.claims["sub_type"]
    else:
        iss = headers[ISS_HEADER]
        sub = headers[SUB_HEADER]
        sub_type = headers[SUB_TYPE_HEADER]

    return {
        "type": PrincipalType(sub_type),
        "authority": iss,
        "id": sub,
    }
