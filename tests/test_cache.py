from app.cache import ResultCache
from app.config import settings
from app.models import DomainStatus


def test_ttl_mapping():
    assert ResultCache.ttl_for(DomainStatus.FREE) == settings.ttl_free
    assert ResultCache.ttl_for(DomainStatus.REGISTERED) == settings.ttl_registered
    assert ResultCache.ttl_for(DomainStatus.PENDING_DELETE) == settings.ttl_pending
    assert ResultCache.ttl_for(DomainStatus.ERROR) == settings.ttl_error


def test_ttl_free_is_short():
    # Policy: 'free' must be cached for at most a few minutes.
    assert settings.ttl_free <= 900
