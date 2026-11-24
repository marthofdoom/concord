//! The web console: a handful of static files embedded in the binary.
//!
//! No build step and no external requests. The assets carry no inline script
//! or style, so a strict CSP (`script-src 'self'; style-src 'self'`) holds;
//! the CSP header itself is the auth layer's to set, not this module's.

use axum::extract::Request;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;

struct Asset {
    path: &'static str,
    content_type: &'static str,
    body: &'static str,
}

const ASSETS: &[Asset] = &[
    Asset {
        path: "/",
        content_type: "text/html; charset=utf-8",
        body: include_str!("../assets/index.html"),
    },
    Asset {
        path: "/ui/app.js",
        content_type: "text/javascript; charset=utf-8",
        body: include_str!("../assets/app.js"),
    },
    Asset {
        path: "/ui/logic.js",
        content_type: "text/javascript; charset=utf-8",
        body: include_str!("../assets/logic.js"),
    },
    Asset {
        path: "/ui/app.css",
        content_type: "text/css; charset=utf-8",
        body: include_str!("../assets/app.css"),
    },
    Asset {
        path: "/ui/favicon.svg",
        content_type: "image/svg+xml",
        body: include_str!("../assets/favicon.svg"),
    },
];

/// FNV-1a: stable across builds and Rust versions, unlike `DefaultHasher`, so
/// an unchanged asset keeps its ETag over a restart.
fn etag(body: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in body.bytes() {
        h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
    }
    format!("\"{h:016x}\"")
}

fn serve(asset: &'static Asset, req: &Request) -> Response {
    let tag = etag(asset.body);
    let unchanged = req
        .headers()
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(',')
                .any(|t| t.trim().trim_start_matches("W/") == tag)
        });
    let mut resp = if unchanged {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        asset.body.into_response()
    };
    let h = resp.headers_mut();
    if !unchanged {
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(asset.content_type),
        );
    }
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::ETAG,
        // Hex in quotes, so this always parses; an empty tag merely never
        // matches.
        HeaderValue::from_str(&tag).unwrap_or(HeaderValue::from_static("")),
    );
    resp
}

/// Generic over the state so it merges into any router without needing its
/// own `with_state`.
pub fn routes<S: Clone + Send + Sync + 'static>() -> Router<S> {
    ASSETS.iter().fold(Router::new(), |r, a| {
        r.route(
            a.path,
            get(move |req: Request| async move { serve(a, &req) }),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn fetch(uri: &str, inm: Option<&str>) -> Response {
        let mut r = Request::get(uri);
        if let Some(v) = inm {
            r = r.header("if-none-match", v);
        }
        routes::<()>()
            .oneshot(r.body(Body::empty()).expect("req"))
            .await
            .expect("resp")
    }

    #[tokio::test]
    async fn serves_each_asset_with_type_and_cache_headers() {
        for a in ASSETS {
            let resp = fetch(a.path, None).await;
            assert_eq!(resp.status(), StatusCode::OK, "{}", a.path);
            assert_eq!(resp.headers()["content-type"], a.content_type);
            assert_eq!(resp.headers()["cache-control"], "no-cache");
            assert_eq!(resp.headers()["x-content-type-options"], "nosniff");
            let tag = resp.headers()["etag"].to_str().expect("etag").to_owned();
            let bytes = resp.into_body().collect().await.expect("body").to_bytes();
            assert_eq!(bytes, a.body.as_bytes());
            // Revalidation with the same tag costs no body.
            let again = fetch(a.path, Some(&tag)).await;
            assert_eq!(again.status(), StatusCode::NOT_MODIFIED, "{}", a.path);
            assert_eq!(again.headers()["etag"], tag.as_str());
        }
    }

    #[tokio::test]
    async fn unknown_ui_path_is_404() {
        assert_eq!(
            fetch("/ui/nope.js", None).await.status(),
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn assets_are_csp_clean_and_self_contained() {
        let banned = [
            "innerHTML",
            "outerHTML",
            "insertAdjacentHTML",
            "document.write",
            "eval(",
            "new Function",
            "style=",
            "setAttribute(\"style\"",
            ".style.",
            "cssText",
        ];
        for a in ASSETS {
            for b in banned {
                assert!(!a.body.contains(b), "{} contains `{b}`", a.path);
            }
            // Inline handlers: onclick= and friends in markup.
            let lower = a.body.to_ascii_lowercase();
            for at in lower.match_indices(" on") {
                let rest = &lower[at.0 + 3..];
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_lowercase())
                    .collect();
                assert!(
                    !(name.len() > 2 && rest[name.len()..].starts_with('=')),
                    "{} has an inline handler `on{name}=`",
                    a.path
                );
            }
            // The SVG namespace is an identifier, not a request.
            let cleaned = a.body.replace("http://www.w3.org/2000/svg", "");
            assert!(
                !cleaned.contains("http://")
                    && !cleaned.contains("https://")
                    && !cleaned.contains("//cdn"),
                "{} references an external URL",
                a.path
            );
        }
        let html = ASSETS[0].body;
        assert!(!html.contains("<script>") && !html.contains("<style"));
    }
}
