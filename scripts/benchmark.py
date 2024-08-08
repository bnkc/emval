import time
import random
import string
import argparse
import logging
import plotly.graph_objects as go
import ipaddress
from typing import Callable, Dict, Any
from tqdm import tqdm

# Import the validators to benchmark
from emval import validate_email as emval_validate
from email_validator import validate_email as email_validator_validate
from verify_email import verify_email


def _generate_random_email() -> str:
    """Generate a random email address with various valid formats."""
    email_types = [
        _generate_basic_email,
        _generate_special_char_email,
        _generate_quoted_local_part_email,
        _generate_domain_literal_email,
    ]
    return random.choice(email_types)()


def _generate_random_length() -> int:
    """Generate a realistic random length for email usernames."""
    return random.randint(1, 64)


def _generate_basic_email() -> str:
    """Generate a basic random email address."""
    length = _generate_random_length()
    domain_length = random.randint(5, 10)
    user = "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
    domain = "".join(random.choices(string.ascii_lowercase, k=domain_length))
    return f"{user}@{domain}.com"


def _generate_special_char_email() -> str:
    """Generate a random email address with special characters."""
    length = _generate_random_length()
    special_chars = "!#$%&'*+-/=?^_`.{|}~"
    user_length = random.randint(1, length)
    user = "".join(
        random.choices(
            string.ascii_lowercase + string.digits + special_chars, k=user_length
        )
    )
    domain_length = random.randint(5, 10)
    domain = "".join(random.choices(string.ascii_lowercase, k=domain_length))
    return f"{user}@{domain}.com"


def _generate_quoted_local_part_email() -> str:
    """Generate a random email address with a quoted local part."""
    length = _generate_random_length()
    special_chars = "!#$%&'*+-/=?^_`.{|}~"
    user_length = random.randint(1, length)
    user = "".join(
        random.choices(
            string.ascii_lowercase + string.digits + special_chars, k=user_length
        )
    )
    domain_length = random.randint(5, 10)
    domain = "".join(random.choices(string.ascii_lowercase, k=domain_length))
    return f'"{user}"@{domain}.com'


def _generate_domain_literal_email() -> str:
    """Generate a random email address with a domain literal."""
    length = _generate_random_length()
    user_length = random.randint(1, length)
    user = "".join(
        random.choices(string.ascii_lowercase + string.digits, k=user_length)
    )
    if random.choice([True, False]):
        # Generate IPv4 address
        ip = str(ipaddress.IPv4Address(random.randint(0, 2**32 - 1)))
    else:
        # Generate IPv6 address
        ip = str(ipaddress.IPv6Address(random.randint(0, 2**128 - 1)))
    return f"{user}@[IPv6:{ip}]" if ":" in ip else f"{user}@[{ip}]"


def _benchmark_validator(validator: Callable[[str], None], num_emails: int) -> float:
    """Benchmark a given email validator.

    Args:
        validator (Callable[[str], None]): The email validator function.
        num_emails (int): Number of emails to validate.

    Returns:
        float: The time taken to validate the emails.
    """
    emails = [_generate_random_email() for _ in range(num_emails)]
    start_time = time.time()
    for email in tqdm(emails, desc=f"Validating with {validator.__name__}"):
        try:
            validator(email)
        except Exception as e:
            logging.debug(f"Validation error for {email}: {e}")
    end_time = time.time()
    return end_time - start_time


def _plot_results(results: Dict[str, float], num_emails: int) -> None:
    """Plot the benchmarking results.

    Args:
        results (Dict[str, float]): The benchmarking results.
        num_emails (int): The number of emails validated.
    """
    sorted_results = sorted(results.items(), key=lambda x: x[1], reverse=True)
    labels, durations = zip(*sorted_results)

    fig = go.Figure()

    fig.add_trace(
        go.Bar(
            x=durations,
            y=labels,
            orientation="h",
            marker=dict(
                color="rgba(0, 51, 102, 0.8)",  # Darker blue color
                line=dict(color="rgba(0, 51, 102, 1.0)", width=1.5),
            ),
        )
    )

    fig.update_layout(
        title=dict(
            text=f"Benchmarking {num_emails} Emails of Various Complexities",
            font=dict(size=20),
            x=0.5,
            xanchor="center",
        ),
        xaxis=dict(
            title="Duration (s)",
            tickvals=list(range(0, int(max(durations)) + 1, 2)),
            ticktext=[f"{tick}s" for tick in range(0, int(max(durations)) + 1, 2)],
            tickfont=dict(size=12, color="rgba(58, 71, 80, 1.0)"),
            gridcolor="rgba(200, 200, 200, 0.3)",
            zeroline=False,
        ),
        yaxis=dict(
            title="",
            tickfont=dict(size=12, color="rgba(58, 71, 80, 1.0)"),
            showgrid=False,  # Remove horizontal grid lines
            zeroline=False,
        ),
        paper_bgcolor="white",
        plot_bgcolor="white",
        showlegend=False,
        margin=dict(l=100, r=20, t=70, b=40),
        height=400,
    )

    for index, value in enumerate(durations):
        fig.add_annotation(
            x=value,
            y=labels[index],
            text=f"{value:.2f}s",
            showarrow=False,
            font=dict(
                color="rgba(58, 71, 80, 1.0)",
                size=12,
            ),
            xanchor="left",
            yanchor="middle",
        )

    fig.write_image("perf.svg")
    fig.show()


def _save_results(results: Dict[str, float], filename: str) -> None:
    """Save benchmarking results to a file.

    Args:
        results (Dict[str, float]): The benchmarking results.
        filename (str): The file name to save the results.
    """
    with open(filename, "w") as f:
        for validator, duration in results.items():
            f.write(f"{validator}: {duration:.4f} seconds\n")


def main() -> None:
    """Main function to parse arguments and run benchmarks."""
    parser = argparse.ArgumentParser(description="Benchmark email validators.")
    parser.add_argument(
        "--num-emails", type=int, default=1000, help="Number of emails to validate"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Print verbose output"
    )
    parser.add_argument(
        "--save-results", type=str, help="File to save the benchmark results"
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    validators: Dict[str, Any] = {
        "emval": emval_validate,
        "python-email-validator": email_validator_validate,
        "verify-email": verify_email,
    }

    results: Dict[str, float] = {}
    for name, validator in validators.items():
        logging.info(f"Benchmarking {name}...")
        duration = _benchmark_validator(validator, num_emails=args.num_emails)
        results[name] = duration
        logging.info(f"{name} took {duration:.4f} seconds")

    _plot_results(results, args.num_emails)

    if args.save_results:
        _save_results(results, args.save_results)


if __name__ == "__main__":
    main()
