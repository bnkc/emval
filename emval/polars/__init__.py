from pathlib import Path
from typing import TYPE_CHECKING
from typing import List

import polars as pl
from polars.plugins import register_plugin_function
from polars._typing import IntoExpr

PLUGIN_PATH = Path(__file__).parent.parent

def validate_email(
    expr: IntoExpr,
    allow_smtputf8: bool,
    allow_empty_local: bool,
    allow_quoted_local: bool,
    allow_domain_literal: bool,
    deliverable_address: bool,
    allowed_special_domains: List[str],
) -> pl.Expr:
    return register_plugin_function(
        plugin_path=PLUGIN_PATH,
        function_name="validate_email",
        args=expr,
        kwargs={
            "allow_smtputf8": allow_smtputf8,
            'allow_empty_local': allow_empty_local,
            'allow_quoted_local': allow_quoted_local,
            'allow_domain_literal': allow_domain_literal,
            'deliverable_address': deliverable_address,
            'allowed_special_domains': allowed_special_domains,
        },
    )