import pytest
from emval.polars import validate_email
from emval import EmailValidator
import polars as pl

@pytest.fixture
def validator():
    return EmailValidator(
        allow_smtputf8=True,
        allow_empty_local=False,
        allow_quoted_local=False,
        allow_domain_literal=False,
        deliverable_address=True,
    )


def test_valid_email_validation(validator):
    df = pl.DataFrame({"email": ["user@example.com"]})
    result = df.with_columns(
        validated=validate_email(
            pl.col("email"),
            allow_smtputf8=True,
            allow_empty_local=False,
            allow_quoted_local=False,
            allow_domain_literal=False,
            deliverable_address=True,
        )
    )

    # Extract validation results
    result = result.with_columns(
        original=pl.col("validated").struct.field("original"),
        normalized=pl.col("validated").struct.field("normalized"),
        is_deliverable=pl.col("validated").struct.field("is_deliverable"),
    )

    assert result.get_column("original")[0] is None
    assert result.get_column("is_deliverable")[0] is None


def test_invalid_email_validation(validator):
    df = pl.DataFrame({"email": ["invalid-email"]})
    result = df.with_columns(
        validated=validate_email(
            pl.col("email"),
            allow_smtputf8=True,
            allow_empty_local=False,
            allow_quoted_local=False,
            allow_domain_literal=False,
            deliverable_address=True,
        )
    )

    # Extract validation results
    result = result.with_columns(
        original=pl.col("validated").struct.field("original"),
        is_deliverable=pl.col("validated").struct.field("is_deliverable"),
    )

    assert result.get_column("original")[0] is None
    assert result.get_column("is_deliverable")[0] is None


def test_empty_email_validation(validator):
    df = pl.DataFrame({"email": [""]})
    result = df.with_columns(
        validated=validate_email(
            pl.col("email"),
            allow_smtputf8=True,
            allow_empty_local=False,
            allow_quoted_local=False,
            allow_domain_literal=False,
            deliverable_address=True,
        )
    )

    # Extract validation results
    result = result.with_columns(
        original=pl.col("validated").struct.field("original"),
        is_deliverable=pl.col("validated").struct.field("is_deliverable"),
    )

    assert result.get_column("original")[0] is None
    assert result.get_column("is_deliverable")[0] is None


def test_multiple_emails_validation(validator):
    df = pl.DataFrame(
        {"email": ["user1@example.com", "invalid-email", "user2@domain.com", ""]}
    )
    result = df.with_columns(
        validated=validate_email(
            pl.col("email"),
            allow_smtputf8=True,
            allow_empty_local=False,
            allow_quoted_local=False,
            allow_domain_literal=False,
            deliverable_address=True,
        )
    )

    # Extract validation results
    result = result.with_columns(
        original=pl.col("validated").struct.field("original"),
        is_deliverable=pl.col("validated").struct.field("is_deliverable"),
    )

    assert len(result) == 4
    assert result.get_column("is_deliverable")[0] is None
    assert result.get_column("is_deliverable")[1] is None
    assert result.get_column("is_deliverable")[2] is True  
    assert result.get_column("is_deliverable")[3] is None