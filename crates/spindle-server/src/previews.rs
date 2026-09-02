//! URL previews — the one endpoint where the server fetches what it's told.
//!
//! That makes it the textbook server-side request forgery vector, and the
//! guard is structured so the dangerous step cannot be reached around: DNS
//! resolution happens inside a vetting resolver that refuses non-global
//! addresses, and the connection is then made to exactly the addresses the
//! vet approved. There is no code path that resolves twice — which is what
//! makes classic DNS-rebinding (answer public once for the check, private
//! once for the fetch) structurally impossible rather than merely checked
//! for.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use spindle_core::keys::{self, Keyspace};
use spindle_store::{FjallStore, ReadView, Store};

use crate::media::Media;
use crate::netguard::{Cidr, VettingResolver, is_global};

/// How much of a page is read looking for its metadata. Everything a
/// preview wants lives in `<head>`; a bound this size is about refusing to
/// stream a 4 GB "page" into memory, not about real documents.
const MAX_HTML_BYTES: usize = 2 * 1024 * 1024;

/// The largest `og:image` that will be rehosted.
const MAX_IMAGE_BYTES: usize = 10 * 1024 * 1024;

/// How long a cached preview serves before being refetched.
const CACHE_SECONDS: u64 = 3600;

pub struct Previews {
    store: Arc<FjallStore>,
    media: Arc<Media>,
    client: reqwest::Client,
    /// The same ranges the resolver honours, for URLs that carry a literal
    /// IP and therefore never reach DNS.
    allowed: Vec<Cidr>,
}

#[derive(Debug)]
pub enum PreviewError {
    /// The URL is refused before any request is made.
    Refused(String),
    /// The fetch itself failed or the response was unusable.
    Unfetchable(String),
    Storage(String),
}

impl std::fmt::Display for PreviewError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(why) => write!(formatter, "refused: {why}"),
            Self::Unfetchable(why) => write!(formatter, "unfetchable: {why}"),
            Self::Storage(why) => write!(formatter, "storage: {why}"),
        }
    }
}

impl Previews {
    /// # Errors
    ///
    /// Returns [`PreviewError`] if an allow-list entry does not parse — a
    /// config error surfaced at startup, not at first use, because a typo'd
    /// range that silently matched nothing would fail closed in a way nobody
    /// notices until previews of the internal wiki stop working, and fail
    /// *open* is not a direction this list can fail in.
    pub fn new(
        store: Arc<FjallStore>,
        media: Arc<Media>,
        allow_private: &[String],
    ) -> Result<Self, PreviewError> {
        let allowed = allow_private
            .iter()
            .map(|entry| Cidr::parse(entry).map_err(PreviewError::Refused))
            .collect::<Result<Vec<_>, _>>()?;
        let resolver = Arc::new(VettingResolver {
            allowed: allowed.clone(),
        });
        // Redirects need their own vet, which lives beside the resolver in
        // `netguard` so the two outbound clients cannot drift apart again.
        let client = reqwest::Client::builder()
            .dns_resolver(resolver)
            .redirect(crate::netguard::redirect_policy(
                allowed.clone(),
                "previewable",
            ))
            .timeout(Duration::from_secs(20))
            .user_agent("spindle-url-preview")
            .build()
            .map_err(|error| PreviewError::Unfetchable(error.to_string()))?;
        Ok(Self {
            store,
            media,
            client,
            allowed,
        })
    }

    /// Fetch (or serve from cache) the `OpenGraph` preview of `url`.
    ///
    /// # Errors
    ///
    /// Returns [`PreviewError`] if the URL is refused, unfetchable, or the
    /// cache cannot be read or written.
    pub async fn preview(&self, url: &str, now: u64) -> Result<Value, PreviewError> {
        let parsed: reqwest::Url = url
            .parse()
            .map_err(|_| PreviewError::Refused("not a URL".to_owned()))?;
        // Scheme first: file://, gopher://, ftp:// and friends have no
        // business here regardless of where they point.
        if parsed.scheme() != "http" && parsed.scheme() != "https" {
            return Err(PreviewError::Refused(
                "only http and https can be previewed".to_owned(),
            ));
        }
        // A literal IP in the URL never touches DNS, so the resolver hook
        // never sees it — vet it here, against the same judgement.
        if let Ok(literal) = parsed
            .host_str()
            .unwrap_or_default()
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            && !self.client_allows(literal)
        {
            return Err(PreviewError::Refused(
                "that address is not previewable".to_owned(),
            ));
        }

        let cache_key = cache_key(url);
        if let Some(bytes) = ReadView::get(self.store.as_ref(), &cache_key)
            .map_err(|e| PreviewError::Storage(e.to_string()))?
            && let Ok(cached) = serde_json::from_slice::<Value>(&bytes)
            && cached["fetched_at"]
                .as_u64()
                .is_some_and(|at| now.saturating_sub(at) < CACHE_SECONDS)
        {
            return Ok(cached["og"].clone());
        }

        let og = self.fetch_preview(&parsed).await?;
        let record = json!({ "fetched_at": now, "og": og });
        Store::put(
            self.store.as_ref(),
            &cache_key,
            record.to_string().as_bytes(),
        )
        .map_err(|error| PreviewError::Storage(error.to_string()))?;
        Ok(og)
    }

    fn client_allows(&self, address: IpAddr) -> bool {
        is_global(address) || self.allowed.iter().any(|cidr| cidr.contains(address))
    }

    async fn fetch_preview(&self, url: &reqwest::Url) -> Result<Value, PreviewError> {
        let response = self
            .client
            .get(url.clone())
            .send()
            .await
            .map_err(|error| PreviewError::Unfetchable(error.to_string()))?;
        if !response.status().is_success() {
            return Err(PreviewError::Unfetchable(format!(
                "the page answered {}",
                response.status()
            )));
        }
        let html = read_limited(response, MAX_HTML_BYTES).await?;
        let html = String::from_utf8_lossy(&html);
        let mut og = extract_open_graph(&html);

        // Rehost og:image so the client never fetches the third-party URL
        // itself — that would leak every reader's IP to the previewed site.
        if let Some(image_url) = og["og:image"].as_str().map(str::to_owned)
            && let Ok(resolved) = url.join(&image_url)
            && (resolved.scheme() == "http" || resolved.scheme() == "https")
            && let Ok(mxc) = self.rehost_image(&resolved).await
        {
            og["og:image"] = json!(mxc.0);
            og["matrix:image:size"] = json!(mxc.1);
        } else if og["og:image"].is_string() {
            // No rehost, no preview image: handing back the original URL
            // would turn every rendering client into the leak above.
            og.as_object_mut()
                .expect("og is always an object")
                .remove("og:image");
        }
        Ok(og)
    }

    async fn rehost_image(&self, url: &reqwest::Url) -> Result<(String, u64), PreviewError> {
        let response = self
            .client
            .get(url.clone())
            .send()
            .await
            .map_err(|error| PreviewError::Unfetchable(error.to_string()))?;
        if !response.status().is_success() {
            return Err(PreviewError::Unfetchable("image fetch failed".to_owned()));
        }
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("application/octet-stream")
            .split(';')
            .next()
            .unwrap_or_default()
            .to_owned();
        if !content_type.starts_with("image/") {
            return Err(PreviewError::Unfetchable(
                "og:image did not serve an image".to_owned(),
            ));
        }
        let bytes = read_limited(response, MAX_IMAGE_BYTES).await?;
        let size = bytes.len() as u64;
        let media_id = self
            .media
            .put(&bytes, &content_type, None, "url-preview")
            .await
            .map_err(|error| PreviewError::Storage(error.to_string()))?;
        Ok((self.media.mxc(&media_id), size))
    }
}

/// Read at most `limit` bytes of a response body, refusing bigger.
async fn read_limited(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, PreviewError> {
    let mut collected = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| PreviewError::Unfetchable(error.to_string()))?
    {
        collected.extend_from_slice(&chunk);
        if collected.len() > limit {
            return Err(PreviewError::Unfetchable(
                "the page is too large".to_owned(),
            ));
        }
    }
    Ok(collected)
}

/// Cache key: the URL's hash, not the URL — URLs are unbounded and
/// user-chosen, and keys should be neither.
fn cache_key(url: &str) -> Vec<u8> {
    let mut key = vec![keys::KEY_SCHEMA_VERSION, Keyspace::UrlPreview as u8];
    key.extend_from_slice(blake3::hash(url.as_bytes()).as_bytes());
    key
}

/// Pull the `OpenGraph` tags (and fallbacks) out of a page's HTML.
///
/// A scanner, not a parser: previews want a handful of `<meta>` properties
/// from `<head>`, and pulling in an HTML parsing dependency to read six
/// attributes would be the tail wagging the dog. Malformed HTML degrades to
/// a missing preview field, never to an error.
fn extract_open_graph(html: &str) -> Value {
    let mut og = serde_json::Map::new();
    for tag in html.split('<').skip(1) {
        let Some(end) = tag.find('>') else { continue };
        let tag = &tag[..end];
        if tag.starts_with("meta") {
            let (Some(property), Some(content)) = (
                attribute(tag, "property").or_else(|| attribute(tag, "name")),
                attribute(tag, "content"),
            ) else {
                continue;
            };
            if property.starts_with("og:") && !og.contains_key(&property) {
                og.insert(property, Value::String(decode_entities(&content)));
            }
        }
    }
    // The title fallback, done over the raw text so attributes cannot fake it.
    if !og.contains_key("og:title")
        && let Some(start) = html.find("<title>")
        && let Some(len) = html[start + 7..].find("</title>")
    {
        og.insert(
            "og:title".to_owned(),
            Value::String(decode_entities(html[start + 7..start + 7 + len].trim())),
        );
    }
    Value::Object(og)
}

fn attribute(tag: &str, name: &str) -> Option<String> {
    for quote in ['"', '\''] {
        let pattern = format!("{name}={quote}");
        if let Some(start) = tag.find(&pattern) {
            let rest = &tag[start + pattern.len()..];
            if let Some(end) = rest.find(quote) {
                return Some(rest[..end].to_owned());
            }
        }
    }
    None
}

fn decode_entities(text: &str) -> String {
    text.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
}

#[cfg(test)]
mod guard_tests {
    use std::net::IpAddr;

    use super::{Cidr, extract_open_graph, is_global};

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn every_internal_range_is_refused() {
        // Each of these is a real target something has been burned by.
        for address in [
            "127.0.0.1",        // loopback admin ports
            "10.0.0.1",         // RFC1918
            "172.16.0.1",       // RFC1918
            "192.168.1.1",      // RFC1918
            "169.254.169.254",  // cloud metadata, the classic
            "100.64.0.1",       // CGNAT
            "0.0.0.0",          // unspecified
            "224.0.0.1",        // multicast
            "255.255.255.255",  // broadcast
            "::1",              // v6 loopback
            "fe80::1",          // v6 link-local
            "fd00::1",          // ULA
            "::ffff:127.0.0.1", // v4-mapped smuggling
            "::ffff:169.254.169.254",
        ] {
            assert!(!is_global(ip(address)), "{address} must be refused");
        }
    }

    #[test]
    fn ordinary_public_addresses_pass() {
        for address in ["93.184.216.34", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(is_global(ip(address)), "{address} must pass");
        }
    }

    #[test]
    fn cidr_matching_is_exact_about_boundaries() {
        let range = Cidr::parse("127.0.0.0/8").unwrap();
        assert!(range.contains(ip("127.0.0.1")));
        assert!(range.contains(ip("127.255.255.255")));
        assert!(!range.contains(ip("128.0.0.0")));
        assert!(!range.contains(ip("126.255.255.255")));
        // A v4 range never swallows a v6 address.
        assert!(!range.contains(ip("::7f00:1")));

        let single = Cidr::parse("192.168.1.7").unwrap();
        assert!(single.contains(ip("192.168.1.7")));
        assert!(!single.contains(ip("192.168.1.8")));

        assert!(Cidr::parse("10.0.0.0/33").is_err(), "prefix too long");
        assert!(Cidr::parse("not-an-ip/8").is_err());
    }

    #[test]
    fn open_graph_extraction_reads_meta_and_title() {
        let html = r#"<html><head>
            <title>Fallback &amp; Title</title>
            <meta property="og:title" content="Real Title"/>
            <meta property='og:description' content='A &quot;description&quot;'>
            <meta name="og:site_name" content="Example">
        </head><body><p>og:title nothing here</p></body></html>"#;
        let og = extract_open_graph(html);
        assert_eq!(og["og:title"], "Real Title");
        assert_eq!(og["og:description"], "A \"description\"");
        assert_eq!(og["og:site_name"], "Example");

        let bare = extract_open_graph("<title>Only &amp; Title</title>");
        assert_eq!(bare["og:title"], "Only & Title");
    }
}
