use thiserror::Error;

use crate::apl::aps::apsde::ApsdeError;

#[derive(Debug, Error)]
pub enum ApsmeSecurityError {
    #[error("command validation error")]
    CommandValidationError,
    #[error("APSDE error: {0}")]
    ApsdeSapError(#[from] ApsdeError),
}
