//! The CAPTCHA check behind `m.login.recaptcha`.
//!
//! reCAPTCHA, hCaptcha and Turnstile share one wire shape: the client solves
//! a widget, and the server posts `secret` and the client's `response` token
//! to the provider and reads `success`. So one verifier serves all three.
//!
//! The check fails closed. A provider that is down, slow, unreachable or
//! unreadable refuses the registration; it never lets one through. The
//! verification URL goes through the same address vetting as push gateways,
//! so a bad `verify_url` cannot aim the server at an internal address.

use std::net::IpAddr;
use std::time::Duration;

use reqwest::Url;
use serde_json::Value;

use crate::config::CaptchaConfig;
use crate::netguard::{Cidr, VettingResolver, parse_allow_list, permits, redirect_policy};

/// A provider that has not answered by now is treated as refusing.
const TIMEOUT: Duration = Duration::from_secs(5);

pub const STAGE: &str = "m.login.recaptcha";

pub struct Verifier {
    client: reqwest::Client,
    allowed: Vec<Cidr>,
    url: String,
    secret: String,
    site_key: String,
}

impl Verifier {
    /// # Errors
    ///
    /// When the secret file cannot be read, an allow-list entry does not
    /// parse or the client cannot be built: start-up errors, so a captcha
    /// that cannot work does not silently turn registration off or open.
    pub fn new(config: &CaptchaConfig) -> Result<Self, String> {
        let secret = config.resolve_secret()?;
        if secret.is_empty() {
            return Err("registration.captcha: the secret key is empty".to_owned());
        }
        let allowed = parse_allow_list(&config.allow_internal)?;
        let client = reqwest::Client::builder()
            .dns_resolver(std::sync::Arc::new(VettingResolver {
                allowed: allowed.clone(),
            }))
            .redirect(redirect_policy(allowed.clone(), "reachable"))
            .timeout(TIMEOUT)
            .user_agent("spindle-captcha")
            .build()
            .map_err(|error| error.without_url().to_string())?;
        Ok(Self {
            client,
            allowed,
            url: config
                .verify_url
                .clone()
                .unwrap_or_else(|| config.provider.verify_url().to_owned()),
            secret,
            site_key: config.site_key.clone(),
        })
    }

    /// The stage's `params`, in the shape the spec gives.
    #[must_use]
    pub fn params(&self) -> Value {
        serde_json::json!({ "public_key": self.site_key })
    }

    /// Whether the provider accepts `token`. Any failure to ask or to
    /// understand the answer is a refusal, and is logged without the secret.
    pub async fn verify(&self, token: &str, remote_ip: Option<&str>) -> bool {
        match self.ask(token, remote_ip).await {
            Ok(success) => success,
            Err(why) => {
                tracing::warn!("captcha verification failed closed: {why}");
                false
            }
        }
    }

    async fn ask(&self, token: &str, remote_ip: Option<&str>) -> Result<bool, String> {
        let url: Url = self
            .url
            .parse()
            .map_err(|_| "the verify URL is not a URL".to_owned())?;
        // A literal address never reaches the vetting resolver.
        if let Ok(literal) = url
            .host_str()
            .unwrap_or_default()
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            && !permits(&self.allowed, literal)
        {
            return Err("the verify URL is an address this server does not reach".to_owned());
        }
        // The serializer is not `Send`, so it must not live across the await.
        let body = {
            let mut form = form_urlencoded::Serializer::new(String::new());
            form.append_pair("secret", &self.secret)
                .append_pair("response", token);
            if let Some(ip) = remote_ip {
                form.append_pair("remoteip", ip);
            }
            form.finish()
        };
        let response = self
            .client
            .post(url)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .map_err(|error| error.without_url().to_string())?;
        if !response.status().is_success() {
            return Err(format!("the provider answered {}", response.status()));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|error| error.without_url().to_string())?;
        let answer: Value = serde_json::from_slice(&bytes)
            .map_err(|_| "the provider's answer is not JSON".to_owned())?;
        Ok(answer["success"] == Value::Bool(true))
    }
}
