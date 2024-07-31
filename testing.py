# from email_validator import EmailSyntaxError, validate_email, ValidatedEmail
from emv import validate_email

validate_email("\u0300@test")
