//! Shared verification of RS256-signed OpenID Connect ID tokens against a
//! provider's published JSON Web Key Set (JWKS). Used by the native sign-in
//! flows, e.g. "Sign-in with Apple" and "Sign-in with Google".

use futures_util::FutureExt;
use futures_util::future::{BoxFuture, Shared};
use parking_lot::Mutex;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::time::{Duration, SystemTime};

use crate::auth::AuthError;

/// RFC: https://www.rfc-editor.org/info/rfc7517/#section-4
#[allow(unused)]
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct Jwk {
  pub kty: String,
  pub kid: String,
  pub r#use: String,
  pub alg: String,
  pub n: String,
  pub e: String,
}

/// RFC: https://www.rfc-editor.org/info/rfc7517/#section-5
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct JwkSet {
  pub keys: Vec<Jwk>,
}

/// Per-provider cache of the most recent (in-flight or completed) key-set fetch.
pub(crate) type JwkSetCache = Mutex<
  Option<(
    SystemTime,
    Shared<BoxFuture<'static, Result<JwkSet, String>>>,
  )>,
>;

/// Extracts the `kid` header from a JWT without any network access.
pub fn extract_kid(id_token: &str) -> Result<String, AuthError> {
  let Ok(header) = jsonwebtoken::decode_header(id_token) else {
    return Err(AuthError::BadRequest("malformed identity token"));
  };

  if let Some(kid) = header.kid
    && !kid.is_empty()
  {
    return Ok(kid);
  }

  return Err(AuthError::BadRequest(
    "identity token is missing the kid header",
  ));
}

/// Verifies signature and claims (issuer, audience, expiry) of an RS256-signed
/// ID token against the given public keys, selecting the key by `kid`.
pub(crate) fn decode_and_validate_id_token<T: DeserializeOwned>(
  public_keys: &JwkSet,
  id_token: &str,
  issuers: &[&str],
  audiences: &[&str],
) -> Result<T, AuthError> {
  let kid = extract_kid(id_token)?;

  // Find the key.
  let Some(public_key) = public_keys.keys.iter().find(|key| key.kid == kid) else {
    return Err(AuthError::Unauthorized);
  };

  let decoding_key = jsonwebtoken::DecodingKey::from_rsa_components(&public_key.n, &public_key.e)
    .map_err(|err| {
    // Got invalid key from the provider?
    return AuthError::FailedDependency(err.into());
  })?;

  let validation = {
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(audiences);
    validation.set_issuer(issuers);
    validation
  };

  let token_data =
    jsonwebtoken::decode::<T>(id_token, &decoding_key, &validation).map_err(|_err| {
      // Validation failed.
      return AuthError::Unauthorized;
    })?;

  return Ok(token_data.claims);
}

/// Fetches a JWKS from the given URL.
#[cfg_attr(test, allow(unused))]
pub(crate) async fn fetch_jwks(
  http_client: reqwest::Client,
  url: &'static str,
) -> Result<JwkSet, String> {
  let response = http_client
    .get(url)
    .send()
    .await
    .map_err(|err| err.to_string())?;

  return response.json().await.map_err(|err| err.to_string());
}

/// Returns the cached key set if younger than 15 minutes, and otherwise
/// (re-)fetches it. Concurrent callers share a single in-flight fetch and
/// failed fetches are not cached.
pub(crate) async fn fetch_cached<F, Fut>(
  cache: &'static JwkSetCache,
  fetch: F,
  http_client: &reqwest::Client,
) -> Result<JwkSet, String>
where
  F: (Fn(reqwest::Client) -> Fut) + Send + 'static,
  Fut: Future<Output = Result<JwkSet, String>> + Send,
{
  let now = SystemTime::now();
  let is_valid = |ts: SystemTime| -> bool {
    return now
      .duration_since(ts)
      .is_ok_and(|d| d < Duration::from_mins(15));
  };

  let future = {
    let mut lock = cache.lock();
    if let Some((ref ts, ref future)) = *lock
      && is_valid(*ts)
    {
      future.clone()
    } else {
      let http_client = http_client.clone();
      let future = async move {
        fetch(http_client).await.map_err(|err| {
          // Invalidate cache. Defensively avoid deadlocking even if `fetch` returns synchronously.
          if let Some(mut lock) = cache.try_lock_for(Duration::from_millis(10)) {
            *lock = None;
          }

          return err;
        })
      }
      .boxed()
      .shared();

      *lock = Some((now, future.clone()));

      future
    }
  };

  // Await w/o holding the lock.
  return future.await;
}

/// Fixture shared by the native-verification tests, standing in for a
/// provider's signing key and published key set.
#[cfg(test)]
pub mod test_support {
  use base64::prelude::*;
  use rsa::RsaPrivateKey;
  use rsa::pkcs8::EncodePrivateKey;
  use rsa::traits::PublicKeyParts;
  use std::sync::LazyLock;

  use super::*;

  pub const TEST_KEY_ID: &str = "test-key-1";

  /// RSA private key standing in for the provider's signing key.
  fn signing_key() -> &'static RsaPrivateKey {
    static KEY: LazyLock<RsaPrivateKey> = LazyLock::new(|| {
      let mut rng = rand::rng();
      return RsaPrivateKey::new(&mut rng, 2048).unwrap();
    });

    return &KEY;
  }

  pub fn signing_jwt_key() -> jsonwebtoken::EncodingKey {
    let pem = signing_key().to_pkcs8_pem(Default::default()).unwrap();
    return jsonwebtoken::EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();
  }

  pub(crate) fn fixture_keys() -> JwkSet {
    let key = signing_key();
    let test_key = Jwk {
      kty: "RSA".to_string(),
      kid: TEST_KEY_ID.to_string(),
      r#use: "sig".to_string(),
      alg: "RS256".to_string(),
      n: BASE64_URL_SAFE_NO_PAD.encode(key.n().to_be_bytes()),
      e: BASE64_URL_SAFE_NO_PAD.encode(key.e().to_be_bytes()),
    };

    return JwkSet {
      keys: vec![test_key],
    };
  }

  pub fn sign_token(claims: serde_json::Value) -> String {
    let key = signing_jwt_key();
    let header = jsonwebtoken::Header {
      alg: jsonwebtoken::Algorithm::RS256,
      kid: Some(TEST_KEY_ID.to_string()),
      ..Default::default()
    };
    return jsonwebtoken::encode(&header, &claims, &key).unwrap();
  }
}

#[cfg(test)]
mod tests {
  use std::sync::LazyLock;
  use std::sync::atomic::{AtomicUsize, Ordering};

  use base64::prelude::*;

  use super::test_support::*;
  use super::*;

  #[test]
  fn test_extract_kid() {
    assert!(extract_kid("garbage").is_err());
    // Well-formed base64 header without a kid field.
    let header = BASE64_URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#);
    assert!(extract_kid(&format!("{header}.bbb.ccc")).is_err());

    let token = sign_token(serde_json::json!({ "sub": "123" }));
    assert_eq!(extract_kid(&token).unwrap(), TEST_KEY_ID);
  }

  #[test]
  fn any_of_multiple_issuers_and_audiences_is_accepted() {
    #[derive(Deserialize)]
    struct Claims {
      sub: String,
    }

    let exp = (chrono::Utc::now() + chrono::Duration::minutes(10)).timestamp();
    let token = sign_token(serde_json::json!({
      "iss": "issuer-b",
      "aud": "audience-b",
      "exp": exp,
      "sub": "123",
    }));

    let claims: Claims = decode_and_validate_id_token(
      &fixture_keys(),
      &token,
      &["issuer-a", "issuer-b"],
      &["audience-a", "audience-b"],
    )
    .unwrap();
    assert_eq!(claims.sub, "123");

    assert!(matches!(
      decode_and_validate_id_token::<Claims>(
        &fixture_keys(),
        &token,
        &["issuer-a"],
        &["audience-a", "audience-b"],
      ),
      Err(AuthError::Unauthorized)
    ));
    assert!(matches!(
      decode_and_validate_id_token::<Claims>(
        &fixture_keys(),
        &token,
        &["issuer-a", "issuer-b"],
        &["audience-a"],
      ),
      Err(AuthError::Unauthorized)
    ));
  }

  #[tokio::test]
  async fn test_cache() {
    let http_client = reqwest::Client::new();

    type ResultType = Result<JwkSet, String>;

    static CACHE: LazyLock<JwkSetCache> = LazyLock::new(|| Mutex::new(None));
    static CALLED: AtomicUsize = AtomicUsize::new(0);
    static RESULT: LazyLock<parking_lot::Mutex<ResultType>> =
      LazyLock::new(|| parking_lot::Mutex::new(Err("default".to_string())));

    async fn fetch(_: reqwest::Client) -> ResultType {
      CALLED.fetch_add(1, Ordering::SeqCst);
      return RESULT.lock().clone();
    }

    // Make sure, errors are not cached.
    let f0 = fetch_cached(&CACHE, fetch, &http_client);
    let f1 = fetch_cached(&CACHE, fetch, &http_client);
    assert!(f0.await.is_err());
    assert!(f1.await.is_err());
    assert_eq!(2, CALLED.load(Ordering::SeqCst));

    assert!(fetch_cached(&CACHE, fetch, &http_client).await.is_err());
    assert_eq!(3, CALLED.load(Ordering::SeqCst));

    *RESULT.lock() = Ok(JwkSet { keys: vec![] });

    // Make sure success is cached.
    assert!(fetch_cached(&CACHE, fetch, &http_client).await.is_ok());
    assert_eq!(4, CALLED.load(Ordering::SeqCst));

    assert!(fetch_cached(&CACHE, fetch, &http_client).await.is_ok());
    assert_eq!(4, CALLED.load(Ordering::SeqCst));
  }

  #[tokio::test]
  async fn caches_are_independent_per_provider() {
    let http_client = reqwest::Client::new();

    static CACHE_A: LazyLock<JwkSetCache> = LazyLock::new(|| Mutex::new(None));
    static CACHE_B: LazyLock<JwkSetCache> = LazyLock::new(|| Mutex::new(None));

    async fn fetch_a(_: reqwest::Client) -> Result<JwkSet, String> {
      return Ok(fixture_keys());
    }
    async fn fetch_b(_: reqwest::Client) -> Result<JwkSet, String> {
      return Ok(JwkSet { keys: vec![] });
    }

    let a = fetch_cached(&CACHE_A, fetch_a, &http_client).await.unwrap();
    let b = fetch_cached(&CACHE_B, fetch_b, &http_client).await.unwrap();
    assert_eq!(a.keys.len(), 1);
    assert_eq!(b.keys.len(), 0);
  }
}
