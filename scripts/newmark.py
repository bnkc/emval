import time
import random
import string
import argparse
import logging
import matplotlib.pyplot as plt

# Import the validators you want to benchmark
from emv import validate_email as emv_validate
from email_validator import validate_email as email_validator_validate

# from validate_email_address import validate_email as validate_email_address_validate
from validate_email import validate_email as py3_validate_email
# import validators
# from django.core.validators import validate_email as django_validate_email
# from django.core.exceptions import ValidationError
#


# Function to generate a random email
def generate_random_email(length=10):
    domain_length = random.randint(5, 10)
    user = "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
    domain = "".join(random.choices(string.ascii_lowercase, k=domain_length))
    return f"{user}@{domain}.com"


# Benchmarking function
def benchmark_validator(validator, num_emails=100, email_length=10):
    emails = [generate_random_email(email_length) for _ in range(num_emails)]
    start_time = time.time()
    for email in emails:
        try:
            validator(email)
        except Exception as e:
            logging.debug(f"Validation error for {email}: {e}")
    end_time = time.time()
    duration = end_time - start_time
    return duration


def benchmark_validator_with_exception_handling(
    validator, num_emails=100, email_length=10, exception=Exception
):
    emails = [generate_random_email(email_length) for _ in range(num_emails)]
    start_time = time.time()
    for email in emails:
        try:
            validator(email)
        except exception as e:
            logging.debug(f"Validation error for {email}: {e}")
    end_time = time.time()
    duration = end_time - start_time
    return duration


def plot_results(results):
    names = list(results.keys())
    times = list(results.values())

    plt.figure(figsize=(10, 6))
    plt.barh(names, times, color="skyblue")
    plt.xlabel("Time (seconds)")
    plt.title("Email Validator Benchmark")
    plt.show()


def main():
    parser = argparse.ArgumentParser(description="Benchmark email validators.")
    parser.add_argument(
        "--num-emails", type=int, default=100, help="Number of emails to validate"
    )
    parser.add_argument(
        "--email-length",
        type=int,
        default=10,
        help="Length of the random email username",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Print verbose output"
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    validators = {
        "EMV": lambda email: emv_validate(email),
        "email-validator": lambda email: email_validator_validate(email),
        # "validate_email_address": lambda email: validate_email_address_validate(email),
        # "py3-validate-email": lambda email: py3_validate_email(email, check_mx=False),
    }

    results = {}
    for name, validator in validators.items():
        logging.info(f"Benchmarking {name}...")

        duration = benchmark_validator(
            validator, num_emails=args.num_emails, email_length=args.email_length
        )
        results[name] = duration
        logging.info(f"{name} took {duration:.4f} seconds")

    plot_results(results)


if __name__ == "__main__":
    main()
