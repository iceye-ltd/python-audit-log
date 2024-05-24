import pytest

from audit_log.exceptions import AuditPrincipalError
from audit_log.headers import (
    ParsedSPIFFE,
    Principal,
    PrincipalType,
    get_principal_from_headers,
    parse_spiffe,
)

VALID_SPIFFE_HEADER = "URI=spiffe://example.com/ns/namespace/sa/service-account"
INVALID_SPIFFE_HEADER = "URI=invalid-uri"
VALID_SPIFFE_HEADER_INVALID_PATH = (
    "URI=spiffe://example.com//namespace/sa/service-account"
)

VALID_HEADERS = {
    "x-forwarded-client-cert": VALID_SPIFFE_HEADER,
}
INVALID_HEADERS: dict[str, str] = {}

VALID_JWT_HEADERS = {
    "x-jwt-claim-sub": "user123",
    "x-jwt-claim-iss": "example.com",
    "x-jwt-claim-sub-type": "USER",
}
INVALID_JWT_HEADERS = {
    "x-jwt-claim-sub": "user123",
    "x-jwt-claim-iss": "example.com",
    "x-jwt-claim-sub-type": "TEST",
}


def test_parse_spiffe_valid():
    parsed_spiffe = parse_spiffe(VALID_SPIFFE_HEADER)
    assert isinstance(parsed_spiffe, ParsedSPIFFE)
    assert parsed_spiffe.domain == "example.com"
    assert parsed_spiffe.namespace == "namespace"
    assert parsed_spiffe.service_account == "service-account"
    assert (
        parsed_spiffe.spiffe_id
        == "spiffe://example.com/ns/namespace/sa/service-account"
    )


def test_parse_spiffe_invalid():
    with pytest.raises(ValueError, match="Invalid SPIFFE header"):
        parse_spiffe(INVALID_SPIFFE_HEADER)


def test_parse_spiffe_invalid_header():
    with pytest.raises(ValueError, match="Invalid SPIFFE header"):
        parse_spiffe(VALID_SPIFFE_HEADER_INVALID_PATH)


def test_get_principal_from_headers_valid():
    principal = get_principal_from_headers(VALID_HEADERS)
    assert isinstance(principal, Principal)
    assert principal.type == PrincipalType.SYSTEM
    assert principal.authority == "example.com"
    assert principal.id == "spiffe://example.com/ns/namespace/sa/service-account"


def test_get_principal_from_headers_invalid():
    with pytest.raises(AuditPrincipalError, match="Invalid SPIFFE header"):
        get_principal_from_headers(INVALID_HEADERS)


def test_get_principal_from_headers_with_jwt_valid():
    principal = get_principal_from_headers(VALID_JWT_HEADERS)
    assert isinstance(principal, Principal)
    assert principal.type == PrincipalType.USER
    assert principal.authority == "example.com"
    assert principal.id == "user123"


def test_get_principal_from_headers_with_jwt_invalid():
    with pytest.raises(AuditPrincipalError, match="Invalid JWT headers"):
        get_principal_from_headers(INVALID_JWT_HEADERS)


def test_parse_principal_case_insensitive():
    headers = {
        "X-JwT-cLaIm-IsS": "example.com",
        "x-jWt-ClAiM-sUb": "user123",
        "X-JWT-claim-SUB-type": "USER",
    }
    principal = get_principal_from_headers(headers)
    assert principal.type == PrincipalType.USER
    assert principal.authority == "example.com"
    assert principal.id == "user123"


def test_parse_principal_spiffe_insensitive():
    headers = {
        "X-fOrWaRdEd-ClIeNt-CeRt": VALID_SPIFFE_HEADER,
    }
    principal = get_principal_from_headers(headers)
    assert isinstance(principal, Principal)
    assert principal.type == PrincipalType.SYSTEM
    assert principal.authority == "example.com"
    assert principal.id == "spiffe://example.com/ns/namespace/sa/service-account"
