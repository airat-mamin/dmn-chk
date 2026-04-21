import pytest

from app.validator import DomainValidationError, normalize, validate_ru_domain


def test_normalize_strips_scheme_and_path():
    assert normalize("  HTTPS://Example.RU/path?x=1  ") == "example.ru"


def test_normalize_trailing_dot():
    assert normalize("example.ru.") == "example.ru"


def test_validate_ok():
    assert validate_ru_domain("Example.RU") == "example.ru"


def test_validate_idn_ascii_form():
    assert validate_ru_domain("xn--d1acufc.ru") == "xn--d1acufc.ru"


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "example.com",
        "sub.example.ru",         # MVP: no third-level
        "-bad.ru",
        "bad-.ru",
        "bad..ru",
        "ex ample.ru",
        "a" * 64 + ".ru",
    ],
)
def test_validate_rejects(bad):
    with pytest.raises(DomainValidationError):
        validate_ru_domain(bad)
