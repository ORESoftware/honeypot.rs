use std::{error::Error, fs, io, path::PathBuf};

fn replace_exact(
    input: String,
    old: &str,
    new: &str,
    expected: usize,
) -> Result<String, io::Error> {
    let actual = input.matches(old).count();
    if actual != expected {
        return Err(io::Error::other(format!(
            "expected {expected} occurrences of {old:?}, found {actual}"
        )));
    }
    Ok(input.replace(old, new))
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=src/main_unpatched.rs");

    let source = fs::read_to_string("src/main_unpatched.rs")?;
    let mut source = source
        .strip_prefix("#![forbid(unsafe_code)]\n\n")
        .ok_or_else(|| io::Error::other("source is missing the expected crate attribute"))?
        .to_owned();

    source = replace_exact(
        source,
        "    future::pending,\n",
        "    convert::Infallible,\n    future::pending,\n",
        1,
    )?;
    source = replace_exact(
        source,
        "    extract::{ConnectInfo, Request, State},\n",
        "    extract::{ConnectInfo, FromRequestParts, Request, State},\n",
        1,
    )?;
    source = replace_exact(
        source,
        "    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},\n",
        "    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header, request::Parts},\n",
        1,
    )?;
    source = replace_exact(
        source,
        "type HmacSha256 = Hmac<Sha256>;\n",
        r#"type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug)]
struct PeerAddr(Option<SocketAddr>);

impl<S> FromRequestParts<S> for PeerAddr
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|connect_info| connect_info.0),
        ))
    }
}

fn render_to_string<V>(view: impl FnOnce() -> V) -> String
where
    V: RenderHtml,
{
    view().to_html()
}
"#,
        1,
    )?;
    source = replace_exact(
        source,
        "leptos::ssr::render_to_string",
        "render_to_string",
        2,
    )?;
    source = replace_exact(
        source,
        "async fn record_signal(\n",
        "#[allow(clippy::too_many_arguments)]\nasync fn record_signal(\n",
        1,
    )?;
    source = replace_exact(
        source,
        "header::PERMISSIONS_POLICY",
        "axum::http::HeaderName::from_static(\"permissions-policy\")",
        1,
    )?;
    source = replace_exact(
        source,
        "connect: Option<ConnectInfo<SocketAddr>>",
        "PeerAddr(peer): PeerAddr",
        8,
    )?;
    source = replace_exact(source, "connect.map(|value| value.0)", "peer", 8)?;

    let out_dir = PathBuf::from(
        std::env::var_os("OUT_DIR")
            .ok_or_else(|| io::Error::other("Cargo did not provide OUT_DIR"))?,
    );
    fs::write(out_dir.join("main_patched.rs"), source)?;
    Ok(())
}
