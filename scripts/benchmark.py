import timeit
import statistics
import random
import string
from emv import EmailValidator
from email_validator import validate_email, EmailNotValidError, EmailUndeliverableError


# Generate random email addresses
def generate_random_email(valid=True):
    domains = ["example.com", "test.org", "sample.net", "email.co"]
    ipv4 = ["127.0.0.1", "192.168.0.1"]
    ipv6 = ["[::1]", "[2001:db8::1]"]

    # Generate a valid local part
    def generate_local_part():
        local_part_length = random.randint(1, 64)
        local_part = "".join(
            random.choices(
                string.ascii_letters + string.digits + "._%+-", k=local_part_length
            )
        )
        # Ensure the local part does not start or end with a dot, or contain consecutive dots
        while (
            local_part.startswith(".") or local_part.endswith(".") or ".." in local_part
        ):
            local_part = "".join(
                random.choices(
                    string.ascii_letters + string.digits + "._%+-", k=local_part_length
                )
            )
        return local_part

    local_part = generate_local_part()

    if valid:
        domain = random.choice(domains)
        if random.choice([True, False]):
            domain = (
                random.choice(ipv4)
                if random.choice([True, False])
                else random.choice(ipv6)
            )
    else:
        domain = "".join(
            random.choices(
                string.ascii_letters + string.digits, k=random.randint(1, 10)
            )
        )

    return f"{local_part}@{domain}"


# Setup the email addresses to be validated
valid_emails = [generate_random_email(valid=True) for _ in range(10)]
invalid_emails = [generate_random_email(valid=False) for _ in range(10)]

# Initialize your EmailValidator
levs_validator = EmailValidator(allow_domain_literal=True)


# Define the test functions
def test_levs_validator_valid():
    for email in valid_emails:
        levs_validator.email(email)


def test_levs_validator_invalid():
    for email in invalid_emails:
        try:
            levs_validator.email(email)
        except Exception:
            pass


def test_python_validator_valid():
    for email in valid_emails:
        try:
            validate_email(email)
        except (EmailNotValidError, EmailUndeliverableError):
            pass


def test_python_validator_invalid():
    for email in invalid_emails:
        try:
            validate_email(email)
        except (EmailNotValidError, EmailUndeliverableError):
            pass


# Function to run the benchmark
def run_benchmark(func, num_iterations):
    times = timeit.repeat(func, repeat=5, number=num_iterations)
    avg_time = statistics.mean(times) / num_iterations
    stddev_time = statistics.stdev(times) / num_iterations
    return times, avg_time, stddev_time


# Benchmarking
if __name__ == "__main__":
    num_iterations = 1000  # Number of iterations for benchmarking

    # Benchmark your EmailValidator
    (
        levs_validator_valid_times,
        avg_levs_validator_valid,
        stddev_levs_validator_valid,
    ) = run_benchmark(test_levs_validator_valid, num_iterations)
    (
        levs_validator_invalid_times,
        avg_levs_validator_invalid,
        stddev_levs_validator_invalid,
    ) = run_benchmark(test_levs_validator_invalid, num_iterations)

    # Benchmark python-email-validator
    (
        python_validator_valid_times,
        avg_python_validator_valid,
        stddev_python_validator_valid,
    ) = run_benchmark(test_python_validator_valid, num_iterations)
    (
        python_validator_invalid_times,
        avg_python_validator_invalid,
        stddev_python_validator_invalid,
    ) = run_benchmark(test_python_validator_invalid, num_iterations)

    # Calculate percentage differences
    valid_percentage_difference = (
        (avg_python_validator_valid - avg_levs_validator_valid)
        / avg_python_validator_valid
    ) * 100
    invalid_percentage_difference = (
        (avg_python_validator_invalid - avg_levs_validator_invalid)
        / avg_python_validator_invalid
    ) * 100

    # Calculate speedup factors
    valid_speedup_factor = avg_python_validator_valid / avg_levs_validator_valid
    invalid_speedup_factor = avg_python_validator_invalid / avg_levs_validator_invalid

    # Print the results
    print(f"Number of iterations: {num_iterations}")
    print()

    print("Benchmarking Results (in seconds):")
    print("===================================")
    print(f"Levs EmailValidator (valid email):")
    print(
        f"  Average time: {avg_levs_validator_valid:.10f} ± {stddev_levs_validator_valid:.10f} (stddev)"
    )
    print(f"  Times: {levs_validator_valid_times}")
    print()

    print(f"Levs EmailValidator (invalid email):")
    print(
        f"  Average time: {avg_levs_validator_invalid:.10f} ± {stddev_levs_validator_invalid:.10f} (stddev)"
    )
    print(f"  Times: {levs_validator_invalid_times}")
    print()

    print(f"Python EmailValidator (valid email):")
    print(
        f"  Average time: {avg_python_validator_valid:.10f} ± {stddev_python_validator_valid:.10f} (stddev)"
    )
    print(f"  Times: {python_validator_valid_times}")
    print()

    print(f"Python EmailValidator (invalid email):")
    print(
        f"  Average time: {avg_python_validator_invalid:.10f} ± {stddev_python_validator_invalid:.10f} (stddev)"
    )
    print(f"  Times: {python_validator_invalid_times}")
    print()

    print("Performance Comparison:")
    print("=======================")
    print(
        f"Levs EmailValidator is {valid_percentage_difference:.2f}% faster than Python EmailValidator for valid emails."
    )
    print(
        f"Levs EmailValidator is {invalid_percentage_difference:.2f}% faster than Python EmailValidator for invalid emails."
    )
    print(
        f"Levs EmailValidator has a speedup factor of {valid_speedup_factor:.2f} times for valid emails."
    )
    print(
        f"Levs EmailValidator has a speedup factor of {invalid_speedup_factor:.2f} times for invalid emails."
    )
