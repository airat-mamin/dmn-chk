from app.checkers.whois_tcinet import parse_whois
from app.models import DomainStatus

FREE_SAMPLE = """
% By submitting a query to RIPN's Whois Service
% you agree to abide by the following terms of use:
% http://www.ripn.net/about/servpol.html#3.2 (in Russian)
% http://www.ripn.net/about/en/servpol.html#3.2 (in English).

No entries found for the selected source(s).

Last updated on 2026-04-21T12:00:00Z
"""

REGISTERED_SAMPLE = """
domain:     EXAMPLE.RU
nserver:    ns1.example.ru. 192.0.2.1
nserver:    ns2.example.ru. 192.0.2.2
state:      REGISTERED, DELEGATED, VERIFIED
org:        Example LLC
registrar:  RU-CENTER-RU
admin-contact: https://www.nic.ru/whois
created:    2010-05-01T00:00:00Z
paid-till:  2026-05-01T00:00:00Z
free-date:  2026-06-01
source:     TCI

Last updated on 2026-04-21T12:00:00Z
"""

PENDING_DELETE_SAMPLE = """
domain:     EXPIRED.RU
state:      REGISTERED, NOT DELEGATED, PENDING DELETE
registrar:  REG-RU
paid-till:  2025-01-01T00:00:00Z
source:     TCI
"""


def test_whois_free():
    status, fields = parse_whois(FREE_SAMPLE)
    assert status == DomainStatus.FREE
    assert fields == {}


def test_whois_registered():
    status, fields = parse_whois(REGISTERED_SAMPLE)
    assert status == DomainStatus.REGISTERED
    assert fields["registrar"] == "RU-CENTER-RU"
    assert "paid-till" in fields


def test_whois_pending_delete():
    status, _ = parse_whois(PENDING_DELETE_SAMPLE)
    assert status == DomainStatus.PENDING_DELETE
