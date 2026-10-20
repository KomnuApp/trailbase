use serde::Deserialize;

use crate::auth::AuthError;
use crate::auth::jwks::{JwkSet, decode_and_validate_id_token};
#[cfg(not(test))]
use crate::auth::jwks::{JwkSetCache, fetch_cached, fetch_jwks};

/// Google issues ID tokens with either form of the issuer:
///   https://developers.google.com/identity/gsi/web/guides/verify-google-id-token
const GOOGLE_ISSUERS: [&str; 2] = ["https://accounts.google.com", "accounts.google.com"];

#[derive(Clone, Debug, Deserialize)]
pub struct GoogleIdToken {
  /// Google's stable account id. Same as the `id` returned by the userinfo
  /// endpoint used by the web OAuth flow.
  pub sub: String,
  pub email: Option<String>,
  #[serde(default)]
  pub email_verified: Option<bool>,
  pub picture: Option<String>,
  /// Anti-replay nonce. Google embeds the nonce passed by the client verbatim,
  /// e.g. `GetGoogleIdOption.Builder.setNonce` with Android's Credential
  /// Manager. Like for Apple, clients send the SHA-256 hash of their raw nonce.
  #[serde(default)]
  pub nonce: Option<String>,
  // ...Other fields, e.g.:
  // pub aud: String,
  // pub azp: String,
  // pub iss: String,
  // pub exp: i64,
  // pub iat: i64,
  // pub hd: String,
}

/// Verifies signature and claims (issuer, audience, expiry) of a Google ID
/// token against the given public keys, selecting the key by `kid`.
///
/// Required validation documented here:
///   https://developers.google.com/identity/gsi/web/guides/verify-google-id-token
fn decode_and_validate_google_id_token_impl(
  public_keys: &JwkSet,
  id_token: &str,
  audiences: &[&str],
) -> Result<GoogleIdToken, AuthError> {
  return decode_and_validate_id_token(public_keys, id_token, &GOOGLE_ISSUERS, audiences);
}

#[cfg(not(test))]
pub(crate) async fn decode_and_validate_google_id_token(
  http_client: &reqwest::Client,
  id_token: &str,
  audiences: &[&str],
) -> Result<GoogleIdToken, AuthError> {
  const JWK_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";
  static CACHE: std::sync::LazyLock<JwkSetCache> =
    std::sync::LazyLock::new(|| parking_lot::Mutex::new(None));

  let keys = fetch_cached(&CACHE, |client| fetch_jwks(client, JWK_URL), http_client)
    .await
    .map_err(|err| AuthError::FailedDependency(err.into()))?;

  return decode_and_validate_google_id_token_impl(&keys, id_token, audiences);
}

#[cfg(test)]
pub(crate) async fn decode_and_validate_google_id_token(
  _http_client: &reqwest::Client,
  id_token: &str,
  audiences: &[&str],
) -> Result<GoogleIdToken, AuthError> {
  let keys = crate::auth::jwks::test_support::fixture_keys();
  return decode_and_validate_google_id_token_impl(&keys, id_token, audiences);
}

/// Fixture shared by the native-verification tests here and the endpoint
/// tests in `google_native_signin.rs`.
#[cfg(test)]
pub mod test_support {
  use std::sync::LazyLock;

  use super::GOOGLE_ISSUERS;

  pub use crate::auth::jwks::test_support::{sign_token, signing_jwt_key};

  /// Client id of e.g. the Android app's "server client id" (web client).
  pub const CLIENT_ID: &str = "1234-web.apps.googleusercontent.com";
  /// Client id of e.g. the iOS app.
  pub const OTHER_CLIENT_ID: &str = "1234-ios.apps.googleusercontent.com";
  pub static NONCE_HASH: LazyLock<String> = LazyLock::new(|| {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"test");
    return hex::encode(hasher.finalize());
  });

  pub fn valid_claims() -> serde_json::Value {
    return serde_json::json!({
      "iss": GOOGLE_ISSUERS[0],
      "aud": CLIENT_ID,
      "azp": "1234-android.apps.googleusercontent.com",
      "exp": (chrono::Utc::now() + chrono::Duration::minutes(10)).timestamp(),
      "iat": chrono::Utc::now().timestamp(),
      "sub": "110169484474386276334",
      "email": "user@gmail.com",
      "email_verified": true,
      "picture": "https://lh3.googleusercontent.com/a/test",
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
  fn well_formed_native_token_verifies() {
    let claims = decode_and_validate_google_id_token_impl(
      &fixture_keys(),
      &sign_token(valid_claims()),
      &[CLIENT_ID],
    )
    .unwrap();

    assert_eq!(claims.sub, "110169484474386276334");
    assert_eq!(claims.email.as_deref(), Some("user@gmail.com"));
    assert_eq!(claims.email_verified, Some(true));
    assert_eq!(
      claims.picture.as_deref(),
      Some("https://lh3.googleusercontent.com/a/test")
    );
    assert_eq!(claims.nonce.as_deref(), Some(NONCE_HASH.as_str()));
  }

  #[test]
  fn both_issuer_forms_are_accepted() {
    for iss in GOOGLE_ISSUERS {
      let mut claims = valid_claims();
      claims["iss"] = serde_json::json!(iss);

      assert!(
        decode_and_validate_google_id_token_impl(
          &fixture_keys(),
          &sign_token(claims),
          &[CLIENT_ID]
        )
        .is_ok()
      );
    }
  }

  #[test]
  fn any_configured_client_id_is_accepted() {
    let mut claims = valid_claims();
    claims["aud"] = serde_json::json!(OTHER_CLIENT_ID);

    assert!(
      decode_and_validate_google_id_token_impl(
        &fixture_keys(),
        &sign_token(claims),
        &[CLIENT_ID, OTHER_CLIENT_ID]
      )
      .is_ok()
    );
  }

  #[test]
  fn wrong_issuer_is_rejected() {
    let mut claims = valid_claims();
    claims["iss"] = serde_json::json!("https://evil.example.com");

    assert!(
      decode_and_validate_google_id_token_impl(&fixture_keys(), &sign_token(claims), &[CLIENT_ID])
        .is_err()
    );
  }

  #[test]
  fn wrong_audience_is_rejected() {
    let mut claims = valid_claims();
    claims["aud"] = serde_json::json!("someone-elses-app.apps.googleusercontent.com");

    assert!(matches!(
      decode_and_validate_google_id_token_impl(&fixture_keys(), &sign_token(claims), &[CLIENT_ID]),
      Err(AuthError::Unauthorized)
    ));
  }

  #[test]
  fn expired_token_is_rejected() {
    let mut claims = valid_claims();
    claims["exp"] =
      serde_json::json!((chrono::Utc::now() - chrono::Duration::minutes(5)).timestamp());

    assert!(
      decode_and_validate_google_id_token_impl(&fixture_keys(), &sign_token(claims), &[CLIENT_ID])
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
      decode_and_validate_google_id_token_impl(&fixture_keys(), &token, &[CLIENT_ID]),
      Err(AuthError::Unauthorized)
    ));
  }
}
