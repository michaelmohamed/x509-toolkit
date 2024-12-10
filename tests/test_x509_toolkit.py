import base64
from datetime import datetime

import pytest

from x509_toolkit.x509_toolkit import parse_x509_certificate, safe_dn

# Mock certificate data (Base64 DER-encoded X.509 certificate)
VALID_BASE64_CERT = """
MIIDlzCCAn+gAwIBAgIUQgxVkrgZNKHQPr+urL9JaijUBnYwDQYJKoZIhvcNAQELBQAwdDELMAkG
A1UEBhMCVVMxETAPBgNVBAgMCFZpcmdpbmlhMQ8wDQYDVQQHDAZNY0xlYW4xFTATBgNVBAoMDFRl
c3QgQ29tcGFueTEUMBIGA1UECwwLRW5naW5lZXJpbmcxFDASBgNVBAMMC2V4YW1wbGUuY29tMB4X
DTI0MTIwOTE4Mjg0N1oXDTI1MTIwOTE4Mjg0N1owdDELMAkGA1UEBhMCVVMxETAPBgNVBAgMCFZp
cmdpbmlhMQ8wDQYDVQQHDAZNY0xlYW4xFTATBgNVBAoMDFRlc3QgQ29tcGFueTEUMBIGA1UECwwL
RW5naW5lZXJpbmcxFDASBgNVBAMMC2V4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEA4+wMMJVPq7/yR1nPkKT3GZXYGN+d1A3mHbuIuKuZU/yNzHjCdYCcwJv5qH1+zvUH
Sc3XV8URzeyZOWs/UVSJ7RKdzUgG3+F4b57j+5nOPL9JKk82uunNLwZeIzILvBl9ouqIlUMCijAm
39sdM7h97r6Y7xmPMMRJmlrcBIIDU6FM4PqSbDvrLfnDD4VdoBLAapHITYq1IEOtsdlr3T1cY2NC
RQ2wmizZpVd2X3bZLpUE53flhtc2o+FRIx3PZwJ+lUA9ovO7YweURUhjjQ4mmPq63bcWdZTAD1rm
tALigSEprWDvdGgZ27B3sI06Hnduhqpq5BcPBtLAtil5BrmbQQIDAQABoyEwHzAdBgNVHQ4EFgQU
gplG83NBcl3r/IPkVQT+MJk0EZ8wDQYJKoZIhvcNAQELBQADggEBALlTg8JH3WyLrSYMp86wlAxh
HSuJN+wg4i0WIic1cXascahoIoOuiWVCxfJ9Oto8x8k/tI8m/In05DwMFX1moWuu0TQK0ump8u2l
6Ow15MvhYq4Zu9n4u/pBsKTHVVsp+nD9BmzjJwgTYDli69LEVJBooFFDM8a/3LSzQC6SUo1M3OyE
mm9xsu6wdsR5YeNnqvIrLq6PJ1mPJkZWc08euiHqN51w78JYHXhS5ApX9/TQtbr1davcYTXvGbLE
r59PYZiG9HP2xE5gAnHfegtNc1OhLMfndEB/ceytmy8v8rbLZDlnt3kKf2iqVOohsBePuxAZRvzX
FCoD9eIkY/tlA4Q=
"""

# Invalid Base64 string (for failure testing)
INVALID_BASE64_CERT = "INVALIDCERT=="


def test_safe_dn():
    """Test the safe_dn function for normalization and consistency."""
    input_dn = "CN=example.com,OU=Engineering,O=Test Company,L=McLean,ST=Virginia,C=US"
    expected_output = (
        "c=us,cn=example.com,l=mclean,o=test company,ou=engineering,st=virginia"
    )
    assert safe_dn(input_dn) == expected_output, "safe_dn normalization failed"

    # Test for invalid input
    with pytest.raises(ValueError):
        safe_dn("Invalid-DN-Format")


def test_parse_x509_certificate():
    """Test the parse_x509_certificate function with valid and invalid input."""
    # Test valid certificate
    parsed_cert = parse_x509_certificate(VALID_BASE64_CERT)

    assert "serial" in parsed_cert, "Serial number missing from parsed certificate"
    assert "subject_dn" in parsed_cert, "Subject DN missing from parsed certificate"
    assert "issuer_dn" in parsed_cert, "Issuer DN missing from parsed certificate"
    assert (
        "not_valid" in parsed_cert
    ), "Validity information missing from parsed certificate"
    assert isinstance(
        parsed_cert["not_valid"]["before"], datetime
    ), "Not Before is not a datetime object"
    assert isinstance(
        parsed_cert["not_valid"]["after"], datetime
    ), "Not After is not a datetime object"

    # Test invalid Base64 string
    with pytest.raises(ValueError):
        parse_x509_certificate(INVALID_BASE64_CERT)

    # Test invalid DER content
    with pytest.raises(ValueError):
        parse_x509_certificate(base64.b64encode(b"INVALIDCONTENT").decode())


def test_certificate_edge_cases():
    """Test edge cases for parse_x509_certificate."""
    # Empty certificate input
    with pytest.raises(ValueError):
        parse_x509_certificate("")

    # Whitespace-only certificate input
    with pytest.raises(ValueError):
        parse_x509_certificate("   ")


if __name__ == "__main__":
    pytest.main()
