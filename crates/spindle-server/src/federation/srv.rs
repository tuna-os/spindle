//! SRV connection targets with the logical TLS and HTTP authority preserved.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_resolver::TokioResolver;
use rand::RngExt;
use rand::seq::SliceRandom;

use super::FederationError;
use crate::netguard::{Cidr, permits};

#[derive(Clone)]
struct Candidate {
    priority: u16,
    weight: u16,
    client: reqwest::Client,
}

#[derive(Clone)]
pub(super) struct Destination {
    url: String,
    host: Option<String>,
    candidates: Arc<Vec<Candidate>>,
}

impl Destination {
    pub(super) fn fixed(url: String, host: Option<String>, client: reqwest::Client) -> Self {
        Self {
            url,
            host,
            candidates: Arc::new(vec![Candidate {
                priority: 0,
                weight: 0,
                client,
            }]),
        }
    }

    pub(super) fn pool_size(&self) -> usize {
        self.candidates.len()
    }

    pub(super) fn request(&self, method: reqwest::Method, uri: &str) -> Request {
        let mut inner = self.candidates[0]
            .client
            .request(method, format!("{}{uri}", self.url));
        if let Some(host) = &self.host {
            inner = inner.header(reqwest::header::HOST, host);
        }
        Request {
            inner,
            candidates: Arc::clone(&self.candidates),
        }
    }
}

pub(super) struct Request {
    inner: reqwest::RequestBuilder,
    candidates: Arc<Vec<Candidate>>,
}

impl Request {
    pub(super) fn header(mut self, name: &'static str, value: impl AsRef<str>) -> Self {
        self.inner = self.inner.header(name, value.as_ref());
        self
    }

    pub(super) fn timeout(mut self, timeout: Duration) -> Self {
        self.inner = self.inner.timeout(timeout);
        self
    }

    pub(super) fn body(mut self, body: impl Into<reqwest::Body>) -> Self {
        self.inner = self.inner.body(body);
        self
    }

    pub(super) async fn send(self) -> Result<reqwest::Response, reqwest::Error> {
        let request = self.inner.build()?;
        let started = Instant::now();
        let budget = request
            .timeout()
            .copied()
            .unwrap_or(Duration::from_secs(30));
        let ranks: Vec<_> = self
            .candidates
            .iter()
            .map(|c| (c.priority, c.weight))
            .collect();
        let order = weighted_order(&ranks);
        let mut failure = None;
        for index in order {
            let Some(mut attempt) = request.try_clone() else {
                return self.candidates[index].client.execute(request).await;
            };
            *attempt.timeout_mut() = Some(budget.saturating_sub(started.elapsed()));
            match self.candidates[index].client.execute(attempt).await {
                Ok(response) => return Ok(response),
                // Retry only before a request can have been processed. An
                // HTTP response or a response timeout is not a new claim,
                // invite, or transaction to issue to another endpoint.
                Err(error) if error.is_connect() => failure = Some(error),
                Err(error) => return Err(error),
            }
        }
        Err(failure.expect("every destination contains at least one candidate"))
    }
}

/// RFC 2782: lowest priority first, weighted draws without replacement.
/// Shuffle before each draw so zero-weight records do not inherit DNS order.
fn weighted_order(ranks: &[(u16, u16)]) -> Vec<usize> {
    weighted_order_with(ranks, &mut rand::rng())
}

fn weighted_order_with(ranks: &[(u16, u16)], rng: &mut impl rand::Rng) -> Vec<usize> {
    let mut remaining: Vec<usize> = (0..ranks.len()).collect();
    let mut order = Vec::with_capacity(ranks.len());
    while !remaining.is_empty() {
        let priority = remaining.iter().map(|i| ranks[*i].0).min().unwrap();
        let mut group: Vec<usize> = remaining
            .iter()
            .copied()
            .filter(|i| ranks[*i].0 == priority)
            .collect();
        group.shuffle(rng);
        group.sort_by_key(|i| ranks[*i].1 != 0);
        let total: u64 = group.iter().map(|i| u64::from(ranks[*i].1)).sum();
        let draw = rng.random_range(0..=total);
        let mut sum = 0;
        let selected = group
            .into_iter()
            .find(|i| {
                sum += u64::from(ranks[*i].1);
                sum >= draw
            })
            .unwrap();
        order.push(selected);
        remaining.retain(|i| *i != selected);
    }
    order
}

/// Discover modern, then legacy SRV records. An authoritative absence
/// permits fallback; a DNS failure or an explicit unavailable service does not.
pub(super) async fn resolve(
    resolver: &TokioResolver,
    logical: &str,
    allowed: &[Cidr],
    insecure_http: bool,
) -> Result<(Option<Destination>, Instant), FederationError> {
    for service in ["_matrix-fed._tcp", "_matrix._tcp"] {
        let name = format!("{service}.{}.", logical.trim_end_matches('.'));
        let lookup = match resolver.srv_lookup(name).await {
            Ok(lookup) => lookup,
            Err(error) if error.is_no_records_found() || error.is_nx_domain() => continue,
            Err(error) => return Err(FederationError::Refused(format!("SRV lookup: {error}"))),
        };
        let mut until = lookup.valid_until();
        let mut candidates = Vec::new();
        for record in lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                hickory_resolver::proto::rr::RData::SRV(record) => Some(record),
                _ => None,
            })
            .take(100)
        {
            if record.target.is_root() {
                return Err(FederationError::Refused(format!(
                    "{logical} advertises no federation service"
                )));
            }
            if record.port == 0 {
                return Err(FederationError::Refused(
                    "SRV target has port zero".to_owned(),
                ));
            }
            let addresses = match resolver.lookup_ip(record.target.clone()).await {
                Ok(addresses) => addresses,
                Err(error) => {
                    tracing::debug!(%logical, %error, "unreachable SRV target");
                    continue;
                }
            };
            until = until.min(addresses.valid_until());
            let vetted: Vec<SocketAddr> = addresses
                .iter()
                .filter(|ip| permits(allowed, *ip))
                .map(|ip| SocketAddr::new(ip, record.port))
                .collect();
            if vetted.is_empty() {
                continue;
            }
            let client = super::client_builder(allowed)
                .resolve_to_addrs(logical, &vetted)
                .build()
                .map_err(|error| FederationError::Refused(error.to_string()))?;
            candidates.push(Candidate {
                priority: record.priority,
                weight: record.weight,
                client,
            });
        }
        if candidates.is_empty() {
            return Err(FederationError::Refused(format!(
                "{logical} has no reachable SRV target"
            )));
        }
        // No explicit URL port: reqwest must use each DNS override's port.
        // URL authority remains logical for certificate verification and SNI.
        let scheme = if insecure_http { "http" } else { "https" };
        return Ok((
            Some(Destination {
                url: format!("{scheme}://{logical}"),
                host: Some(logical.to_owned()),
                candidates: Arc::new(candidates),
            }),
            until,
        ));
    }
    Ok((None, Instant::now() + Duration::from_secs(60)))
}

#[cfg(test)]
#[path = "srv_tests.rs"]
mod tests;
