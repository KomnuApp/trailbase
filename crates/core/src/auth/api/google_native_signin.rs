use axum::extract::{Json, State};
use serde::Deserialize;
use std::sync::LazyLock;
use utoipa::ToSchema;

use crate::AppState;
use crate::auth::AuthError;
use crate::auth::api::apple_native_signin::verify_nonce_claim;
use crate::auth::api::login::LoginResponse;
use crate::auth::create_external_user::{create_user_for_external_provider, user_by_provider_id};
use crate::auth::google::decode_and_validate_google_id_token;
use crate::auth::oauth::OAuthUser;
use crate::auth::tokens::{FreshTokens, mint_new_tokens};
use crate::config::proto;

#[derive(Debug, Deserialize, ToSchema)]
pub struct GoogleNativeLoginRequest {
  /// The ID token, e.g. `GoogleIdTokenCredential.idToken` from Android's
  /// Credential Manager or `GIDGoogleUser.idToken` from the iOS SDK.
  pub id_token: String,
  /// The raw client-generated nonce whose SHA-256 hash was sent with the
  /// sign-in request (e.g. `GetGoogleIdOption.Builder.setNonce`).
  pub nonce: String,
}

/// Logs users with Google's native sign-in, i.e. a token-exchange Google for TrailBase.
#[utoipa::path(
  post,
  path = "/google/authorize",
  tag = "auth",
  request_body = GoogleNativeLoginRequest,
  responses(
    (status = 200, description = "Converts a verified ID token to auth tokens.", body = LoginResponse),
    (status = 400, description = "Malformed token or nonce mismatch."),
    (status = 401, description = "Missing client ids or token failed signature/issuer/audience/expiry verification."),
    (status = 424, description = "First-time login without a (verified) email claim under the configured user-identifier policy.")
  )
)]
pub(crate) async fn google_native_signin_handler(
  State(state): State<AppState>,
  Json(request): Json<GoogleNativeLoginRequest>,
) -> Result<Json<LoginResponse>, AuthError> {
  // Make sure native_client_ids are configured, otherwise report 404 as if route had not been
  // registered.
  let native_client_ids = state.access_config(|c| c.auth.google_native_client_ids.clone());
  if native_client_ids.is_empty() {
    return Err(AuthError::NotFound);
  }

  // Decode and validate the token.
  let claims = {
    let audiences: Vec<&str> = native_client_ids.iter().map(|id| id.as_str()).collect();
    let claims =
      decode_and_validate_google_id_token(&GOOGLE_HTTP_CLIENT, &request.id_token, &audiences)
        .await?;

    verify_nonce_claim(claims.nonce.as_deref(), &request.nonce)?;

    claims
  };

  // Users are matched by Google's stable `sub` — the same identity space as
  // the web OAuth flow, so a web-created account and a native login resolve
  // to the same account. Creation goes through the same user-identifier
  // policy as the web flow.
  let db_user = match user_by_provider_id(
    state.user_conn(),
    proto::OAuthProviderId::Google,
    claims.sub.clone(),
  )
  .await?
  {
    Some(existing_user) => existing_user,
    None => {
      let user_identifier = state
        .access_config(|c| c.auth.user_identifier)
        .and_then(|ui| ui.try_into().ok())
        .unwrap_or(proto::UserIdentifier::Undefined);

      create_user_for_external_provider(
        state.user_conn(),
        user_identifier,
        OAuthUser {
          provider_user_id: claims.sub,
          provider_id: proto::OAuthProviderId::Google,
          email: claims.email,
          username: None,
          verified: claims.email_verified.unwrap_or(false),
          avatar: claims.picture,
        },
      )
      .await?
    }
  };

  let FreshTokens {
    auth_token_claims: (auth_token_claims, _),
    refresh_token,
  } = mint_new_tokens(&state, &db_user, None).await?;

  let auth_token = state
    .jwt()
    .encode(&auth_token_claims)
    .map_err(|err| AuthError::Internal(err.into()))?;

  return Ok(Json(LoginResponse {
    auth_token,
    refresh_token: refresh_token.map(|(token, _ttl)| token),
    csrf_token: auth_token_claims.csrf_token.into_string(),
  }));
}

/// Shared HTTP client for Google's endpoints: connection pooling instead of a
/// TLS handshake per login. Redirects stay disabled like everywhere else in
/// the OAuth paths (SSRF posture), even though the JWKS URL is a constant.
static GOOGLE_HTTP_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
  reqwest::ClientBuilder::new()
    .redirect(reqwest::redirect::Policy::none())
    .build()
    .expect("reqwest client with disabled redirects always builds")
});

#[cfg(test)]
mod tests {
  use axum::Router;
  use axum_test::TestServer;
  use tower_cookies::CookieManagerLayer;

  use super::*;
  use crate::app_state::{AppState, TestStateOptions, test_state};
  use crate::auth::google::test_support::{CLIENT_ID, OTHER_CLIENT_ID, sign_token, valid_claims};
  use crate::constants::AUTH_API_PATH;

  async fn google_state(
    native_client_ids: &[&str],
    user_identifier: proto::UserIdentifier,
  ) -> AppState {
    let mut config = proto::Config::new_with_custom_defaults();
    config.server.site_url = Some("https://example.org".to_string());
    config.auth.user_identifier = Some(user_identifier as i32);
    config.auth.google_native_client_ids =
      native_client_ids.iter().map(|id| id.to_string()).collect();
    return test_state(Some(TestStateOptions {
      config: Some(config),
      ..Default::default()
    }))
    .await
    .unwrap();
  }

  #[tokio::test]
  async fn valid_native_token_logs_in_and_creates_the_user() {
    let state = google_state(&[CLIENT_ID], proto::UserIdentifier::RequireEmail).await;

    let id_token = sign_token(valid_claims());
    let response = google_native_signin_handler(
      State(state.clone()),
      Json(GoogleNativeLoginRequest {
        id_token,
        nonce: "test".to_string(),
      }),
    )
    .await
    .unwrap()
    .0;

    assert!(!response.auth_token.is_empty());
    assert!(response.refresh_token.is_some_and(|t| !t.is_empty()));

    // The account was created with the verified email from the token.
    let db_user = user_by_provider_id(
      state.user_conn(),
      proto::OAuthProviderId::Google,
      "110169484474386276334".to_string(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(db_user.email.as_deref(), Some("user@gmail.com"));
  }

  #[tokio::test]
  async fn existing_web_oauth_user_is_logged_in() {
    let state = google_state(&[CLIENT_ID], proto::UserIdentifier::RequireEmail).await;

    // A user who previously signed up through the web OAuth flow.
    let web_user = create_user_for_external_provider(
      state.user_conn(),
      proto::UserIdentifier::RequireEmail,
      OAuthUser {
        provider_user_id: "110169484474386276334".to_string(),
        provider_id: proto::OAuthProviderId::Google,
        email: Some("user@gmail.com".to_string()),
        username: None,
        verified: true,
        avatar: None,
      },
    )
    .await
    .unwrap();

    let response = google_native_signin_handler(
      State(state.clone()),
      Json(GoogleNativeLoginRequest {
        id_token: sign_token(valid_claims()),
        nonce: "test".to_string(),
      }),
    )
    .await
    .unwrap()
    .0;
    assert!(!response.auth_token.is_empty());

    let db_user = user_by_provider_id(
      state.user_conn(),
      proto::OAuthProviderId::Google,
      "110169484474386276334".to_string(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(db_user.id, web_user.id);
  }

  #[tokio::test]
  async fn any_configured_client_id_is_accepted() {
    let state = google_state(
      &[CLIENT_ID, OTHER_CLIENT_ID],
      proto::UserIdentifier::RequireEmail,
    )
    .await;

    let mut claims = valid_claims();
    claims["aud"] = serde_json::json!(OTHER_CLIENT_ID);

    let response = google_native_signin_handler(
      State(state),
      Json(GoogleNativeLoginRequest {
        id_token: sign_token(claims),
        nonce: "test".to_string(),
      }),
    )
    .await
    .unwrap()
    .0;

    assert!(!response.auth_token.is_empty());
  }

  #[tokio::test]
  async fn foreign_client_id_audience_is_unauthorized() {
    let state = google_state(&[CLIENT_ID], proto::UserIdentifier::RequireEmail).await;

    let mut claims = valid_claims();
    claims["aud"] = serde_json::json!("someone-elses-app.apps.googleusercontent.com");

    let result = google_native_signin_handler(
      State(state),
      Json(GoogleNativeLoginRequest {
        id_token: sign_token(claims),
        nonce: "test".to_string(),
      }),
    )
    .await;

    assert!(matches!(result, Err(AuthError::Unauthorized)));
  }

  #[tokio::test]
  async fn nonce_mismatch_is_rejected() {
    let state = google_state(&[CLIENT_ID], proto::UserIdentifier::RequireEmail).await;

    let result = google_native_signin_handler(
      State(state),
      Json(GoogleNativeLoginRequest {
        id_token: sign_token(valid_claims()),
        nonce: "wrong-nonce".to_string(),
      }),
    )
    .await;

    assert!(matches!(
      result,
      Err(AuthError::BadRequest("nonce mismatch"))
    ));
  }

  #[tokio::test]
  async fn missing_nonce_claim_is_rejected() {
    let state = google_state(&[CLIENT_ID], proto::UserIdentifier::RequireEmail).await;

    let mut claims = valid_claims();
    claims.as_object_mut().unwrap().remove("nonce");

    let result = google_native_signin_handler(
      State(state),
      Json(GoogleNativeLoginRequest {
        id_token: sign_token(claims),
        nonce: "test".to_string(),
      }),
    )
    .await;

    assert!(matches!(result, Err(AuthError::BadRequest(_))));
  }

  #[tokio::test]
  async fn first_login_with_unverified_email_is_rejected() {
    let state = google_state(&[CLIENT_ID], proto::UserIdentifier::RequireEmail).await;

    let mut claims = valid_claims();
    claims["email_verified"] = serde_json::json!(false);

    let result = google_native_signin_handler(
      State(state),
      Json(GoogleNativeLoginRequest {
        id_token: sign_token(claims),
        nonce: "test".to_string(),
      }),
    )
    .await;

    assert!(matches!(result, Err(AuthError::FailedDependency(_))));
  }

  #[tokio::test]
  async fn missing_native_client_ids_fails_closed_as_not_found() {
    let state = google_state(&[], proto::UserIdentifier::RequireEmail).await;

    let result = google_native_signin_handler(
      State(state),
      Json(GoogleNativeLoginRequest {
        id_token: sign_token(valid_claims()),
        nonce: "test".to_string(),
      }),
    )
    .await;

    assert!(matches!(result, Err(AuthError::NotFound)));
  }

  /// The route is mounted and answers through the real OAuth router: a
  /// structurally invalid token is a local 400 (no network), and the route
  /// exists at all.
  #[tokio::test]
  async fn google_native_login_route_is_mounted_and_rejects_garbage() {
    let state = google_state(&[CLIENT_ID], proto::UserIdentifier::RequireEmail).await;

    let router: Router = Router::from(crate::auth::auth_router(
      &state.get_config(),
      /* dev_mode= */ false,
      /* has_root= */ false,
    ))
    .layer(CookieManagerLayer::new())
    .with_state(state);
    let server = TestServer::new(router);

    let response = server
      .post(&format!("/{AUTH_API_PATH}/google/authorize"))
      .json(&serde_json::json!({
        "id_token": "garbage",
        "nonce": "test",
      }))
      .await;

    response.assert_status(axum::http::StatusCode::BAD_REQUEST);
  }

  /// Without configured client ids, the route is not registered at all.
  #[tokio::test]
  async fn google_native_login_route_is_not_mounted_without_client_ids() {
    let state = google_state(&[], proto::UserIdentifier::RequireEmail).await;

    let router: Router = Router::from(crate::auth::auth_router(
      &state.get_config(),
      /* dev_mode= */ false,
      /* has_root= */ false,
    ))
    .layer(CookieManagerLayer::new())
    .with_state(state);
    let server = TestServer::new(router);

    let response = server
      .post(&format!("/{AUTH_API_PATH}/google/authorize"))
      .json(&serde_json::json!({
        "id_token": "garbage",
        "nonce": "test",
      }))
      .await;

    response.assert_status(axum::http::StatusCode::NOT_FOUND);
  }
}
