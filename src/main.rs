#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    env,
    future::pending,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    body::Bytes,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use hmac::{Hmac, Mac};
use ipnet::IpNet;
use leptos::prelude::*;
use serde::Serialize;
use serde_json::json;
use sha2::Sha256;
use thiserror::Error;
use tokio::{net::TcpListener, sync::Mutex, sync::Semaphore, time::timeout};
use tower_http::{catch_panic::CatchPanicLayer, limit::RequestBodyLimitLayer};
use tracing_subscriber::EnvFilter;

type HmacSha256 = Hmac<Sha256>;

const POLICY_VERSION: &str = "ores.honeypot.response.v1";
const TOKEN_PREFIX: &str = "ores_hp_v1";
const LURES: [(&str, &str); 6] = [
    ("env", "/.env"),
    ("git", "/.git/config"),
    ("backup", "/backup/config.json"),
    ("admin", "/admin/login"),
    ("auth", "/api/v1/auth"),
    ("api-backup", "/api/v1/backup"),
];

#[derive(Debug, Error)]
enum ConfigError {
    #[error("required configuration variable {0} is missing")]
    Missing(&'static str),
    #[error("configuration variable {name} is invalid: {reason}")]
    Invalid {
        name: &'static str,
        reason: String,
    },
    #[error("configuration variables TELEMETRY_HMAC_KEY and LURE_HMAC_KEY must be different")]
    ReusedKey,
}

#[derive(Clone)]
struct Settings {
    bind_addr: SocketAddr,
    public_origin: String,
    generation: String,
    telemetry_key: Arc<[u8]>,
    lure_key: Arc<[u8]>,
    trusted_proxy_cidrs: Arc<[IpNet]>,
    max_body_bytes: usize,
    max_concurrency: usize,
    request_timeout: Duration,
}

impl Settings {
    fn from_env() -> Result<Self, ConfigError> {
        let telemetry_key = required_secret("TELEMETRY_HMAC_KEY")?;
        let lure_key = required_secret("LURE_HMAC_KEY")?;
        if telemetry_key == lure_key {
            return Err(ConfigError::ReusedKey);
        }

        let bind_addr = parse_env("BIND_ADDR", "0.0.0.0:8080")?;
        let max_body_bytes = parse_env("MAX_BODY_BYTES", "8192")?;
        let max_concurrency = parse_env("MAX_CONCURRENCY", "64")?;
        let timeout_seconds: u64 = parse_env("REQUEST_TIMEOUT_SECONDS", "5")?;
        if max_body_bytes == 0 || max_body_bytes > 65_536 {
            return Err(ConfigError::Invalid {
                name: "MAX_BODY_BYTES",
                reason: "must be between 1 and 65536".to_owned(),
            });
        }
        if max_concurrency == 0 || max_concurrency > 4_096 {
            return Err(ConfigError::Invalid {
                name: "MAX_CONCURRENCY",
                reason: "must be between 1 and 4096".to_owned(),
            });
        }
        if timeout_seconds == 0 || timeout_seconds > 30 {
            return Err(ConfigError::Invalid {
                name: "REQUEST_TIMEOUT_SECONDS",
                reason: "must be between 1 and 30".to_owned(),
            });
        }

        let trusted_proxy_cidrs = parse_proxy_cidrs(
            &env::var("TRUSTED_PROXY_CIDRS").unwrap_or_default(),
        )?;

        Ok(Self {
            bind_addr,
            public_origin: env::var("PUBLIC_ORIGIN")
                .unwrap_or_else(|_| "http://127.0.0.1:8080".to_owned()),
            generation: sanitize_component(
                &env::var("LURE_GENERATION").unwrap_or_else(|_| "local".to_owned()),
            ),
            telemetry_key: Arc::from(telemetry_key.into_bytes()),
            lure_key: Arc::from(lure_key.into_bytes()),
            trusted_proxy_cidrs: Arc::from(trusted_proxy_cidrs),
            max_body_bytes,
            max_concurrency,
            request_timeout: Duration::from_secs(timeout_seconds),
        })
    }

    #[cfg(test)]
    fn for_test() -> Self {
        Self {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            public_origin: "https://decoy.example.invalid".to_owned(),
            generation: "test-generation".to_owned(),
            telemetry_key: Arc::from(b"telemetry-key-that-is-longer-than-32-bytes".as_slice()),
            lure_key: Arc::from(b"lure-key-that-is-different-and-longer-than-32".as_slice()),
            trusted_proxy_cidrs: Arc::from(Vec::<IpNet>::new()),
            max_body_bytes: 8_192,
            max_concurrency: 64,
            request_timeout: Duration::from_secs(5),
        }
    }
}

fn required_secret(name: &'static str) -> Result<String, ConfigError> {
    let value = env::var(name).map_err(|_| ConfigError::Missing(name))?;
    if value.len() < 32 {
        return Err(ConfigError::Invalid {
            name,
            reason: "must contain at least 32 bytes".to_owned(),
        });
    }
    Ok(value)
}

fn parse_env<T>(name: &'static str, default: &str) -> Result<T, ConfigError>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    let raw = env::var(name).unwrap_or_else(|_| default.to_owned());
    raw.parse::<T>().map_err(|error| ConfigError::Invalid {
        name,
        reason: error.to_string(),
    })
}

fn parse_proxy_cidrs(raw: &str) -> Result<Vec<IpNet>, ConfigError> {
    raw.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            entry
                .parse::<IpNet>()
                .map_err(|error| ConfigError::Invalid {
                    name: "TRUSTED_PROXY_CIDRS",
                    reason: error.to_string(),
                })
        })
        .collect()
}

fn sanitize_component(value: &str) -> String {
    let sanitized: String = value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
        .take(40)
        .collect();
    if sanitized.is_empty() {
        "local".to_owned()
    } else {
        sanitized
    }
}

#[derive(Clone)]
struct AppState {
    settings: Arc<Settings>,
    tokens: Arc<BTreeMap<&'static str, String>>,
    ledger: Arc<Mutex<EvidenceLedger>>,
    gate: Arc<Semaphore>,
}

impl AppState {
    fn new(settings: Settings) -> Self {
        let tokens = LURES
            .iter()
            .map(|(lure, _)| (*lure, derive_honeytoken(&settings, lure)))
            .collect();
        let max_concurrency = settings.max_concurrency;
        Self {
            settings: Arc::new(settings),
            tokens: Arc::new(tokens),
            ledger: Arc::new(Mutex::new(EvidenceLedger::default())),
            gate: Arc::new(Semaphore::new(max_concurrency)),
        }
    }

    fn token(&self, lure: &'static str) -> &str {
        self.tokens
            .get(lure)
            .map_or("ores_hp_v1_invalid", String::as_str)
    }

    fn detect_token(&self, headers: &HeaderMap, body: &[u8]) -> Option<&'static str> {
        self.tokens.iter().find_map(|(lure, token)| {
            let token_bytes = token.as_bytes();
            let header_match = headers
                .values()
                .any(|value| contains_subslice(value.as_bytes(), token_bytes));
            let body_match = contains_subslice(body, token_bytes);
            (header_match || body_match).then_some(*lure)
        })
    }
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && needle.len() <= haystack.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn derive_honeytoken(settings: &Settings, lure: &str) -> String {
    let material = format!("{}:{}", settings.generation, lure);
    let digest = hmac_hex(&settings.lure_key, b"lure-token", material.as_bytes());
    let suffix = digest.get(..20).map_or(digest.as_str(), |value| value);
    format!(
        "{TOKEN_PREFIX}_{}_{}_{}",
        sanitize_component(lure),
        settings.generation,
        suffix
    )
}

fn hmac_hex(key: &[u8], purpose: &[u8], value: &[u8]) -> String {
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return String::new();
    };
    mac.update(purpose);
    mac.update(&[0]);
    mac.update(value);
    hex::encode(mac.finalize().into_bytes())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Signal {
    LureViewed,
    CredentialUsed,
    ExploitProbe,
}

#[derive(Debug)]
struct EvidenceRecord {
    observed_at: Instant,
    signal: Signal,
    lure: String,
}

#[derive(Default)]
struct EvidenceLedger {
    by_actor: HashMap<String, VecDeque<EvidenceRecord>>,
}

#[derive(Clone, Debug, Serialize)]
struct PolicyDecision {
    action: &'static str,
    ttl_seconds: Option<u64>,
    reason: &'static str,
    policy_version: &'static str,
}

impl EvidenceLedger {
    fn record(&mut self, actor: &str, signal: Signal, lure: &str) -> PolicyDecision {
        let now = Instant::now();
        let records = self.by_actor.entry(actor.to_owned()).or_default();
        records.retain(|record| {
            now.duration_since(record.observed_at) <= Duration::from_secs(86_400)
        });
        records.push_back(EvidenceRecord {
            observed_at: now,
            signal,
            lure: lure.to_owned(),
        });
        while records.len() > 128 {
            let _ = records.pop_front();
        }

        let credential_count = records
            .iter()
            .filter(|record| record.signal == Signal::CredentialUsed)
            .count();
        let exploit_count = records
            .iter()
            .filter(|record| record.signal == Signal::ExploitProbe)
            .count();
        let view_count = records
            .iter()
            .filter(|record| record.signal == Signal::LureViewed)
            .count();
        let lure_families: BTreeSet<&str> = records
            .iter()
            .map(|record| record.lure.as_str())
            .collect();

        if credential_count >= 3 && lure_families.len() >= 3 {
            decision(
                "human_review",
                Some(604_800),
                "sustained credential activity across independent lure families",
            )
        } else if credential_count >= 2 || exploit_count >= 3 {
            decision(
                "temporary_block",
                Some(86_400),
                "repeated high-confidence activity",
            )
        } else if credential_count == 1 {
            decision(
                "managed_challenge",
                Some(3_600),
                "exact synthetic credential reuse",
            )
        } else if lure_families.len() >= 3 {
            decision(
                "managed_challenge",
                Some(1_800),
                "multiple independent lure families discovered",
            )
        } else if view_count >= 20 {
            decision(
                "rate_limit",
                Some(900),
                "high-rate low-confidence reconnaissance",
            )
        } else {
            decision(
                "observe",
                None,
                "insufficient evidence for automated friction",
            )
        }
    }
}

fn decision(
    action: &'static str,
    ttl_seconds: Option<u64>,
    reason: &'static str,
) -> PolicyDecision {
    PolicyDecision {
        action,
        ttl_seconds,
        reason,
        policy_version: POLICY_VERSION,
    }
}

#[derive(Debug, Serialize)]
struct EventCore {
    schema: &'static str,
    event_id: String,
    observed_at_unix_ms: u128,
    actor_pseudonym: String,
    user_agent_pseudonym: String,
    method: String,
    path: String,
    request_bytes: usize,
    signal: Signal,
    lure: String,
    cloudflare_ray_id: Option<String>,
    cloudflare_country: Option<String>,
    cloudflare_asn: Option<u32>,
    decision: PolicyDecision,
}

#[derive(Debug, Serialize)]
struct SecurityEvent {
    core: EventCore,
    signature_hmac_sha256: String,
}

async fn record_signal(
    state: &AppState,
    peer: Option<SocketAddr>,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    signal: Signal,
    lure: &str,
    request_bytes: usize,
) -> PolicyDecision {
    let immediate_ip = peer
        .map(|address| address.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let trusted_proxy = state
        .settings
        .trusted_proxy_cidrs
        .iter()
        .any(|network| network.contains(&immediate_ip));
    let client_ip = if trusted_proxy {
        trusted_client_ip(headers).unwrap_or(immediate_ip)
    } else {
        immediate_ip
    };

    let actor_digest = hmac_hex(
        &state.settings.telemetry_key,
        b"actor-ip",
        client_ip.to_string().as_bytes(),
    );
    let actor_pseudonym = short_digest(&actor_digest, 24);
    let user_agent = headers
        .get(header::USER_AGENT)
        .map_or(&[][..], HeaderValue::as_bytes);
    let user_agent_digest = hmac_hex(
        &state.settings.telemetry_key,
        b"user-agent",
        user_agent,
    );
    let user_agent_pseudonym = short_digest(&user_agent_digest, 24);

    let decision = state
        .ledger
        .lock()
        .await
        .record(&actor_pseudonym, signal, lure);
    let observed_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis());
    let path = uri.path().to_owned();
    let event_material = format!(
        "{observed_at_unix_ms}:{actor_pseudonym}:{}:{path}:{signal:?}:{lure}",
        method.as_str()
    );
    let event_id_digest = hmac_hex(
        &state.settings.telemetry_key,
        b"event-id",
        event_material.as_bytes(),
    );

    let core = EventCore {
        schema: "ores.honeypot.security-event.v1",
        event_id: short_digest(&event_id_digest, 32),
        observed_at_unix_ms,
        actor_pseudonym,
        user_agent_pseudonym,
        method: method.as_str().to_owned(),
        path,
        request_bytes,
        signal,
        lure: lure.to_owned(),
        cloudflare_ray_id: trusted_proxy
            .then(|| sanitized_header(headers, "cf-ray", 80))
            .flatten(),
        cloudflare_country: trusted_proxy
            .then(|| sanitized_header(headers, "cf-ipcountry", 2))
            .flatten(),
        cloudflare_asn: trusted_proxy
            .then(|| sanitized_header(headers, "cf-asn", 12))
            .flatten()
            .and_then(|value| value.parse::<u32>().ok()),
        decision: decision.clone(),
    };
    let serialized = serde_json::to_vec(&core).unwrap_or_default();
    let signature_hmac_sha256 = hmac_hex(
        &state.settings.telemetry_key,
        b"event-signature",
        &serialized,
    );
    let event = SecurityEvent {
        core,
        signature_hmac_sha256,
    };
    let encoded = serde_json::to_string(&event).unwrap_or_else(|_| {
        "{\"schema\":\"ores.honeypot.serialization-error.v1\"}".to_owned()
    });
    tracing::info!(target: "security_event", event = %encoded);
    decision
}

fn short_digest(digest: &str, length: usize) -> String {
    digest
        .get(..length.min(digest.len()))
        .map_or_else(|| digest.to_owned(), ToOwned::to_owned)
}

fn trusted_client_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get("cf-connecting-ip")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<IpAddr>().ok())
}

fn sanitized_header(headers: &HeaderMap, name: &'static str, max_len: usize) -> Option<String> {
    let value = headers.get(name)?.to_str().ok()?.trim();
    if value.is_empty()
        || value.len() > max_len
        || !value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | ':')
        })
    {
        return None;
    }
    Some(value.to_owned())
}

fn build_router(settings: Settings) -> Router {
    let max_body_bytes = settings.max_body_bytes;
    let state = AppState::new(settings);
    Router::new()
        .route("/", get(index))
        .route("/admin/login", get(admin_login))
        .route("/.env", get(dot_env))
        .route("/.git/config", get(git_config))
        .route("/backup/config.json", get(backup_config))
        .route("/api/v1/auth", post(credential_sink))
        .route("/api/v1/backup", get(api_backup).post(credential_sink))
        .route("/robots.txt", get(robots))
        .route("/healthz", get(health))
        .route("/readyz", get(health))
        .fallback(fallback)
        .layer(RequestBodyLimitLayer::new(max_body_bytes))
        .layer(CatchPanicLayer::new())
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

async fn guard(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let permit = match timeout(
        Duration::from_millis(100),
        state.gate.clone().acquire_owned(),
    )
    .await
    {
        Ok(Ok(permit)) => permit,
        _ => {
            return secured_response(
                StatusCode::TOO_MANY_REQUESTS,
                "text/plain",
                "busy\n",
            );
        }
    };

    let response = timeout(state.settings.request_timeout, next.run(request)).await;
    drop(permit);
    match response {
        Ok(response) => with_security_headers(response),
        Err(_) => secured_response(StatusCode::GATEWAY_TIMEOUT, "text/plain", "timeout\n"),
    }
}

fn with_security_headers(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        ),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    headers.insert(
        header::PERMISSIONS_POLICY,
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=(), usb=()"),
    );
    response
}

fn secured_response(status: StatusCode, content_type: &'static str, body: &'static str) -> Response {
    let mut response = (status, body).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    with_security_headers(response)
}

async fn index(
    State(state): State<AppState>,
    connect: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> Response {
    let _ = record_signal(
        &state,
        connect.map(|value| value.0),
        &headers,
        &method,
        &uri,
        Signal::LureViewed,
        "landing",
        0,
    )
    .await;
    render_page(
        "Northbridge Operations",
        "Internal service administration",
        &state.settings.public_origin,
    )
}

async fn admin_login(
    State(state): State<AppState>,
    connect: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> Response {
    let _ = record_signal(
        &state,
        connect.map(|value| value.0),
        &headers,
        &method,
        &uri,
        Signal::LureViewed,
        "admin",
        0,
    )
    .await;
    render_login()
}

fn render_page(title: &'static str, subtitle: &'static str, origin: &str) -> Response {
    let origin = origin.to_owned();
    let markup = leptos::ssr::render_to_string(move || {
        view! {
            <html lang="en">
                <head>
                    <meta charset="utf-8"/>
                    <meta name="viewport" content="width=device-width, initial-scale=1"/>
                    <title>{format!("{title} | Northbridge")}</title>
                </head>
                <body style="margin:0;background:#0b1220;color:#dbeafe;font-family:ui-monospace,monospace;min-height:100vh">
                    <main style="max-width:760px;margin:0 auto;padding:72px 24px">
                        <p style="letter-spacing:.14em;text-transform:uppercase;color:#60a5fa">"Northbridge Systems"</p>
                        <h1 style="font-size:42px;margin:12px 0">{title}</h1>
                        <p style="font-size:18px;color:#94a3b8">{subtitle}</p>
                        <section style="margin-top:40px;padding:24px;border:1px solid #1e3a5f;border-radius:12px;background:#111827">
                            <p>"Control plane status: operational"</p>
                            <p>"Primary origin: "<code>{origin}</code></p>
                            <a href="/admin/login" style="display:inline-block;margin-top:16px;padding:12px 18px;background:#1d4ed8;color:white;text-decoration:none;border-radius:7px">"Administrator sign in"</a>
                        </section>
                    </main>
                </body>
            </html>
        }
    });
    Html(format!("<!doctype html>{markup}")).into_response()
}

fn render_login() -> Response {
    let markup = leptos::ssr::render_to_string(move || {
        view! {
            <html lang="en">
                <head>
                    <meta charset="utf-8"/>
                    <meta name="viewport" content="width=device-width, initial-scale=1"/>
                    <title>"Administrator sign in"</title>
                </head>
                <body style="margin:0;background:#0b1220;color:#dbeafe;font-family:ui-monospace,monospace;min-height:100vh">
                    <main style="max-width:460px;margin:0 auto;padding:72px 24px">
                        <h1>"Administrator sign in"</h1>
                        <p style="color:#94a3b8">"Use your assigned service account."</p>
                        <form method="post" action="/api/v1/auth" style="display:grid;gap:16px;margin-top:32px">
                            <label>"Account"<input name="account" autocomplete="username" style="display:block;width:100%;box-sizing:border-box;padding:12px;margin-top:6px"/></label>
                            <label>"Access key"<input name="access_key" type="password" autocomplete="current-password" style="display:block;width:100%;box-sizing:border-box;padding:12px;margin-top:6px"/></label>
                            <button type="submit" style="padding:12px;background:#1d4ed8;color:white;border:0;border-radius:7px">"Continue"</button>
                        </form>
                    </main>
                </body>
            </html>
        }
    });
    Html(format!("<!doctype html>{markup}")).into_response()
}

async fn dot_env(
    State(state): State<AppState>,
    connect: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> Response {
    let _ = record_signal(
        &state,
        connect.map(|value| value.0),
        &headers,
        &method,
        &uri,
        Signal::LureViewed,
        "env",
        0,
    )
    .await;
    let body = format!(
        "APP_ENV=production\nAPP_ORIGIN={}\nDATABASE_URL=postgresql://svc_honey:{}@db.internal.invalid:5432/control\nBACKUP_API_KEY={}\n",
        state.settings.public_origin,
        state.token("env"),
        state.token("api-backup"),
    );
    text_response(StatusCode::OK, "text/plain; charset=utf-8", body)
}

async fn git_config(
    State(state): State<AppState>,
    connect: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> Response {
    let _ = record_signal(
        &state,
        connect.map(|value| value.0),
        &headers,
        &method,
        &uri,
        Signal::LureViewed,
        "git",
        0,
    )
    .await;
    let body = format!(
        "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://svc-honey:{}@git.internal.invalid/northbridge/control-plane.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n",
        state.token("git"),
    );
    text_response(StatusCode::OK, "text/plain; charset=utf-8", body)
}

async fn backup_config(
    State(state): State<AppState>,
    connect: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> Response {
    let _ = record_signal(
        &state,
        connect.map(|value| value.0),
        &headers,
        &method,
        &uri,
        Signal::LureViewed,
        "backup",
        0,
    )
    .await;
    let document = json!({
        "service": "northbridge-backup",
        "endpoint": "https://backup.internal.invalid/v1",
        "account": "svc-backup",
        "access_key": state.token("backup"),
        "region": "archive-1"
    });
    json_response(StatusCode::OK, document)
}

async fn api_backup(
    State(state): State<AppState>,
    connect: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> Response {
    let _ = record_signal(
        &state,
        connect.map(|value| value.0),
        &headers,
        &method,
        &uri,
        Signal::LureViewed,
        "api-backup",
        0,
    )
    .await;
    json_response(
        StatusCode::OK,
        json!({
            "name": "northbridge-nightly",
            "status": "standby",
            "token": state.token("api-backup"),
            "upload": "https://archive.internal.invalid/v1/upload"
        }),
    )
}

async fn credential_sink(
    State(state): State<AppState>,
    connect: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Response {
    let detected = state.detect_token(&headers, &body);
    let signal = if detected.is_some() {
        Signal::CredentialUsed
    } else {
        Signal::ExploitProbe
    };
    let lure = detected.unwrap_or("credential-sink");
    let decision = record_signal(
        &state,
        connect.map(|value| value.0),
        &headers,
        &method,
        &uri,
        signal,
        lure,
        body.len(),
    )
    .await;
    json_response(
        StatusCode::UNAUTHORIZED,
        json!({
            "error": "authentication_failed",
            "request_status": "rejected",
            "retry_after_seconds": decision.ttl_seconds
        }),
    )
}

async fn robots() -> Response {
    text_response(
        StatusCode::OK,
        "text/plain; charset=utf-8",
        "User-agent: *\nDisallow: /admin/\nDisallow: /.env\nDisallow: /.git/\nDisallow: /backup/\nDisallow: /api/v1/backup\n".to_owned(),
    )
}

async fn health() -> Response {
    json_response(StatusCode::OK, json!({ "status": "ok" }))
}

async fn fallback(
    State(state): State<AppState>,
    connect: Option<ConnectInfo<SocketAddr>>,
    request: Request,
) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let headers = request.headers().clone();
    if suspicious_path(uri.path()) {
        let _ = record_signal(
            &state,
            connect.map(|value| value.0),
            &headers,
            &method,
            &uri,
            Signal::ExploitProbe,
            "generic-probe",
            0,
        )
        .await;
    }
    json_response(StatusCode::NOT_FOUND, json!({ "error": "not_found" }))
}

fn suspicious_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [
        "wp-login",
        "phpmyadmin",
        ".aws",
        "actuator",
        "vendor/phpunit",
        "cgi-bin",
        "server-status",
        "boaform",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn text_response(status: StatusCode, content_type: &'static str, body: String) -> Response {
    let mut response = (status, body).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

fn json_response(status: StatusCode, value: serde_json::Value) -> Response {
    let body = serde_json::to_string(&value)
        .unwrap_or_else(|_| "{\"error\":\"serialization\"}".to_owned());
    text_response(status, "application/json; charset=utf-8", body)
}

async fn shutdown_signal() {
    let control_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                let _ = signal.recv().await;
            }
            Err(_) => pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = pending::<()>();

    tokio::select! {
        _ = control_c => {},
        _ = terminate => {},
    }
}

fn initialize_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("honeypot_rs=info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .flatten_event(true)
        .try_init();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    initialize_tracing();
    let settings = Settings::from_env()?;
    let bind_addr = settings.bind_addr;
    let listener = TcpListener::bind(bind_addr).await?;
    let app = build_router(settings);
    tracing::info!(address = %bind_addr, "honeypot listener ready");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[test]
    fn generated_tokens_are_vendor_neutral_and_deterministic() {
        let settings = Settings::for_test();
        let first = derive_honeytoken(&settings, "env");
        let second = derive_honeytoken(&settings, "env");
        assert_eq!(first, second);
        assert!(first.starts_with("ores_hp_v1_env_test-generation_"));
        for forbidden in ["AKIA", "ghp_", "github_pat_", "sk_live_", "CF-"] {
            assert!(!first.contains(forbidden));
        }
    }

    #[test]
    fn query_string_is_not_part_of_recorded_path() {
        let uri: Uri = "/wp-login.php?password=do-not-record"
            .parse()
            .unwrap_or_else(|error| unreachable!("static URI must parse: {error}"));
        assert_eq!(uri.path(), "/wp-login.php");
    }

    #[test]
    fn policy_is_reversible_and_escalates_on_exact_token_use() {
        let mut ledger = EvidenceLedger::default();
        let first = ledger.record("actor", Signal::CredentialUsed, "env");
        assert_eq!(first.action, "managed_challenge");
        assert_eq!(first.ttl_seconds, Some(3_600));
        let second = ledger.record("actor", Signal::CredentialUsed, "git");
        assert_eq!(second.action, "temporary_block");
        assert_eq!(second.ttl_seconds, Some(86_400));
    }

    #[tokio::test]
    async fn env_lure_exposes_only_a_synthetic_token() {
        let app = build_router(Settings::for_test());
        let request = Request::builder()
            .uri("/.env")
            .body(Body::empty())
            .unwrap_or_else(|error| unreachable!("static request must build: {error}"));
        let response = app
            .oneshot(request)
            .await
            .unwrap_or_else(|error| unreachable!("router is infallible: {error}"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| unreachable!("body collection must succeed: {error}"))
            .to_bytes();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("ores_hp_v1_env_test-generation_"));
        assert!(text.contains(".invalid"));
        assert!(!text.contains("AKIA"));
    }

    #[tokio::test]
    async fn exact_token_reuse_is_rejected() {
        let settings = Settings::for_test();
        let token = derive_honeytoken(&settings, "env");
        let app = build_router(settings);
        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/auth")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap_or_else(|error| unreachable!("static request must build: {error}"));
        let response = app
            .oneshot(request)
            .await
            .unwrap_or_else(|error| unreachable!("router is infallible: {error}"));
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn raw_ip_is_not_present_in_pseudonym() {
        let raw = "203.0.113.44";
        let digest = hmac_hex(
            b"telemetry-key-that-is-longer-than-32-bytes",
            b"actor-ip",
            raw.as_bytes(),
        );
        assert!(!digest.contains(raw));
        assert_eq!(digest.len(), 64);
    }
}
