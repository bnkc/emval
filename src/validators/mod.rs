pub mod domain;
pub mod email;
pub mod local_part;
pub mod utils;

pub use domain::{validate_deliverability, validate_domain};
pub use local_part::validate_local_part;
pub use utils::*;
