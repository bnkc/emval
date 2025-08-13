use polars::prelude::*;
use pyo3_polars::derive::polars_expr;
use serde::Deserialize;

use crate::models::EmailValidator;

#[derive(Deserialize)]
struct ValidateEmailKwargs {
    allow_smtputf8: bool,
    allow_empty_local: bool,
    allow_quoted_local: bool,
    allow_domain_literal: bool,
    deliverable_address: bool,
}

fn validate_email_struct(_input_fields: &[Field]) -> PolarsResult<Field> {
    let fields = vec![
        Field::new("original".into(), DataType::String),
        Field::new("normalized".into(), DataType::String),
        Field::new("local_part".into(), DataType::String),
        Field::new("domain_address".into(), DataType::String),
        Field::new("domain_name".into(), DataType::String),
        Field::new("is_deliverable".into(), DataType::Boolean),
    ];
    
    Ok(Field::new(
        "validated".into(),
        DataType::Struct(fields),
    ))
}

#[polars_expr(output_type_func=validate_email_struct)]
pub fn validate_email(inputs: &[Series], kwargs: ValidateEmailKwargs) -> PolarsResult<Series> {
    let input = &inputs[0];
    let input = input.cast(&DataType::String)?;
    let ca = input.str().unwrap();

    let email_validator = EmailValidator {
        allow_smtputf8: kwargs.allow_smtputf8,
        allow_empty_local: kwargs.allow_empty_local,
        allow_quoted_local: kwargs.allow_quoted_local,
        allow_domain_literal: kwargs.allow_domain_literal,
        deliverable_address: kwargs.deliverable_address,
    };

    let mut original_builder = StringChunkedBuilder::new("original".into(), ca.len());
    let mut normalized_builder = StringChunkedBuilder::new("normalized".into(), ca.len());
    let mut local_part_builder = StringChunkedBuilder::new("local_part".into(), ca.len());
    let mut domain_address_builder = StringChunkedBuilder::new("domain_address".into(), ca.len());
    let mut domain_name_builder = StringChunkedBuilder::new("domain_name".into(), ca.len());
    let mut is_deliverable_builder = BooleanChunkedBuilder::new("is_deliverable".into(), ca.len());

    for email in ca.iter() {
        match email {
            Some(em) => match email_validator.validate_email(em) {
                Ok(ve) => {
                    original_builder.append_value(ve.original);
                    normalized_builder.append_value(ve.normalized);
                    local_part_builder.append_value(ve.local_part);
                    domain_address_builder
                        .append_option(ve.domain_address.map(|ip| ip.to_string()));
                    domain_name_builder.append_value(ve.domain_name);
                    is_deliverable_builder.append_value(ve.is_deliverable);
                }
                Err(_) => {
                    original_builder.append_null();
                    normalized_builder.append_null();
                    local_part_builder.append_null();
                    domain_address_builder.append_null();
                    domain_name_builder.append_null();
                    is_deliverable_builder.append_null();
                }
            },
            None => {
                original_builder.append_null();
                normalized_builder.append_null();
                local_part_builder.append_null();
                domain_address_builder.append_null();
                domain_name_builder.append_null();
                is_deliverable_builder.append_null();
            }
        }
    }

    let original = original_builder.finish();
    let normalized = normalized_builder.finish();
    let local_part = local_part_builder.finish();
    let domain_address = domain_address_builder.finish();
    let domain_name = domain_name_builder.finish();
    let is_deliverable = is_deliverable_builder.finish();

    let fields = vec![
        original.into_series(),
        normalized.into_series(),
        local_part.into_series(),
        domain_address.into_series(),
        domain_name.into_series(),
        is_deliverable.into_series(),
    ];
    StructChunked::from_series("validated".into(), ca.len(), fields.iter())
        .map(|ca| ca.into_series())
}
