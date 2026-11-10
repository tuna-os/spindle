//! `m.login.terms`: a policy a new account accepts before it registers.
//!
//! The session that carries acceptance to the next stage is in
//! [`crate::registration_stages`].

use serde_json::{Value, json};

use crate::AppState;

pub const STAGE: &str = "m.login.terms";

/// Whether registration asks for the policy.
#[must_use]
pub fn enabled(state: &AppState) -> bool {
    state.config.registration.terms_url.is_some()
}

/// The stage's `params`, in the shape the spec gives.
#[must_use]
pub fn params(state: &AppState) -> Value {
    let config = &state.config.registration;
    json!({
        "policies": {
            "terms_of_service": {
                "version": config.terms_version,
                "en": { "name": config.terms_name, "url": config.terms_url },
            }
        }
    })
}
