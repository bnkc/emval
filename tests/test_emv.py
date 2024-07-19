import pytest
from emv import EmailValidator


def test_sum_as_string():
    validator = EmailValidator()
    assert validator.email("example@domain.com")
    with pytest.raises(Exception):
        validator.email("plainaddress")
