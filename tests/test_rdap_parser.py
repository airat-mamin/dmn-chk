from app.checkers.rdap import parse_rdap_status
from app.models import DomainStatus


def test_rdap_registered_default():
    assert parse_rdap_status({"status": ["active", "server transfer prohibited"]}) == DomainStatus.REGISTERED


def test_rdap_pending_delete():
    assert parse_rdap_status({"status": ["pending delete"]}) == DomainStatus.PENDING_DELETE


def test_rdap_redemption():
    assert parse_rdap_status({"status": ["redemption period"]}) == DomainStatus.REDEMPTION_PERIOD


def test_rdap_missing_status_is_registered():
    # RDAP body without 'status' key still means domain exists (200 OK).
    assert parse_rdap_status({}) == DomainStatus.REGISTERED
