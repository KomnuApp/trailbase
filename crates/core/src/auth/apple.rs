use serde::Deserialize;

use crate::auth::AuthError;
use crate::auth::jwks::{JwkSet, decode_and_validate_id_token};
#[cfg(not(test))]
use crate::auth::jwks::{JwkSetCache, fetch_cached, fetch_jwks};

const APPLE_ISSUER: &str = "https://appleid.apple.com";

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum Boolean {
  String(String),
  Bool(bool),
}

impl Boolean {
  pub fn value(&self) -> bool {
    return match self {
      Boolean::Bool(v) => *v,
      Boolean::String(s) if s.to_lowercase() == "true" => true,
      Boolean::String(_) => false,
    };
  }
}

#[derive(Clone, Debug, Deserialize)]
pub struct AppleIdToken {
  pub sub: String,
  pub email: Option<String>,
  pub email_verified: Option<Boolean>,
  /// Anti-replay nonce. Only present when the authorization request carried
  /// one — always the case for the native Sign in with Apple flow, where the
  /// client sends the SHA-256 hash of its raw nonce with the request.
  #[serde(default)]
  pub nonce: Option<String>,
  // ...Other fields, e.g.:
  // pub aud: String,
  // pub iss: String,
  // pub exp: i64,
  // pub iat: i64,
}

/// Verifies signature and claims (issuer, audience, expiry) of an Apple
/// identity token against the given public keys, selecting the key by `kid`.
///
/// Required validation documented here:
///   https://developer.apple.com/documentation/signinwithapple/verifying-a-user#Verify-the-identity-token
fn decode_and_validate_apple_id_token_impl(
  public_keys: &JwkSet,
  id_token: &str,
  audience: &str,
) -> Result<AppleIdToken, AuthError> {
  return decode_and_validate_id_token(public_keys, id_token, &[APPLE_ISSUER], &[audience]);
}

#[cfg(not(test))]
pub(crate) async fn decode_and_validate_apple_id_token(
  http_client: &reqwest::Client,
  id_token: &str,
  audience: &str,
) -> Result<AppleIdToken, AuthError> {
  const JWK_URL: &str = "https://appleid.apple.com/auth/keys";
  static CACHE: std::sync::LazyLock<JwkSetCache> =
    std::sync::LazyLock::new(|| parking_lot::Mutex::new(None));

  let keys = fetch_cached(&CACHE, |client| fetch_jwks(client, JWK_URL), http_client)
    .await
    .map_err(|err| AuthError::FailedDependency(err.into()))?;

  return decode_and_validate_apple_id_token_impl(&keys, id_token, audience);
}

#[cfg(test)]
pub(crate) async fn decode_and_validate_apple_id_token(
  _http_client: &reqwest::Client,
  id_token: &str,
  audience: &str,
) -> Result<AppleIdToken, AuthError> {
  let keys = crate::auth::jwks::test_support::fixture_keys();
  return decode_and_validate_apple_id_token_impl(&keys, id_token, audience);
}

/// Fixture shared by the native-verification tests here and the endpoint
/// tests in `apple_native_signin.rs`.
#[cfg(test)]
pub mod test_support {
  use std::sync::LazyLock;

  use super::APPLE_ISSUER;

  pub use crate::auth::jwks::test_support::{sign_token, signing_jwt_key};

  pub const APP_ID: &str = "org.test";
  pub static NONCE_HASH: LazyLock<String> = LazyLock::new(|| {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"test");
    return hex::encode(hasher.finalize());
  });

  pub fn valid_claims() -> serde_json::Value {
    return serde_json::json!({
      "iss": APPLE_ISSUER,
      "aud": APP_ID,
      "exp": (chrono::Utc::now() + chrono::Duration::minutes(10)).timestamp(),
      "iat": chrono::Utc::now().timestamp(),
      "sub": "001234.abcdef.1234",
      "email": "user@privaterelay.appleid.com",
      "email_verified": true,
      "nonce": *NONCE_HASH,
    });
  }
}

#[cfg(test)]
mod tests {
  use super::test_support::*;
  use super::*;
  use crate::auth::jwks::test_support::fixture_keys;

  #[test]
  fn test_apple_boolean() {
    use serde_json::{from_value, json};

    // Apple may return strings or booleans: https://developer.apple.com/forums/thread/746352
    let v0 = from_value::<AppleIdToken>(json!({
            "sub": "123",
            "email_verified": "TruE",
    }))
    .unwrap();
    assert_eq!(true, v0.email_verified.unwrap().value());

    let v1 = from_value::<AppleIdToken>(json!({
            "sub": "123",
            "email_verified": "Anything Else",
    }))
    .unwrap();
    assert_eq!(false, v1.email_verified.unwrap().value());

    let v2 = from_value::<AppleIdToken>(json!({
            "sub": "123",
            "email_verified": false,
    }))
    .unwrap();
    assert_eq!(false, v2.email_verified.unwrap().value());

    let v3 = from_value::<AppleIdToken>(json!({
            "sub": "123",
            "email_verified": true,
    }))
    .unwrap();
    assert_eq!(true, v3.email_verified.unwrap().value());
  }

  #[test]
  fn well_formed_native_token_verifies() {
    let claims =
      decode_and_validate_apple_id_token_impl(&fixture_keys(), &sign_token(valid_claims()), APP_ID)
        .unwrap();

    assert_eq!(claims.sub, "001234.abcdef.1234");
    assert_eq!(
      claims.email.as_deref(),
      Some("user@privaterelay.appleid.com")
    );
    assert!(claims.email_verified.is_some_and(|v| v.value()));
    assert_eq!(claims.nonce.as_deref(), Some(NONCE_HASH.as_str()));
  }

  #[test]
  fn wrong_issuer_is_rejected() {
    let mut claims = valid_claims();
    claims["iss"] = serde_json::json!("https://evil.example.com");

    assert!(
      decode_and_validate_apple_id_token_impl(&fixture_keys(), &sign_token(claims), APP_ID)
        .is_err()
    );
  }

  #[test]
  fn expired_token_is_rejected() {
    let mut claims = valid_claims();
    claims["exp"] =
      serde_json::json!((chrono::Utc::now() - chrono::Duration::minutes(5)).timestamp());

    assert!(
      decode_and_validate_apple_id_token_impl(&fixture_keys(), &sign_token(claims), APP_ID)
        .is_err()
    );
  }

  #[test]
  fn unknown_kid_is_rejected() {
    let key = signing_jwt_key();
    let header = jsonwebtoken::Header {
      alg: jsonwebtoken::Algorithm::RS256,
      kid: Some("unknown-kid".to_string()),
      ..Default::default()
    };
    let token = jsonwebtoken::encode(&header, &valid_claims(), &key).unwrap();

    assert!(matches!(
      decode_and_validate_apple_id_token_impl(&fixture_keys(), &token, APP_ID),
      Err(AuthError::Unauthorized)
    ));
  }
}
