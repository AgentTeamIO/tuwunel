use axum::{
	Json,
	extract::{Path, State},
	response::IntoResponse,
};
use http::{HeaderMap, StatusCode, header::AUTHORIZATION};
use ruma::OwnedServerName;
use serde::{Deserialize, Serialize};

type AdminResult<T> = Result<T, (StatusCode, Json<ErrorResponse>)>;

// ──────────────────────────── Request / Response types ────────────────────────

#[derive(Debug, Deserialize)]
pub(crate) struct CreateVhostRequest {
	pub server_name: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct VhostResponse {
	pub server_name: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub verify_key: Option<String>,
	pub is_bootstrap: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct ListVhostsResponse {
	pub vhosts: Vec<VhostResponse>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ErrorResponse {
	pub error: String,
}

// ──────────────────────────── Auth helper ─────────────────────────────────────

/// Validate `Authorization: Bearer {token}` against `config.admin_token`.
/// Returns `Ok(())` on success, or an HTTP error response on failure.
fn require_admin_token(
	services: &tuwunel_service::Services,
	headers: &HeaderMap,
) -> AdminResult<()> {
	let admin_token = services
		.server
		.config
		.admin_token
		.as_deref()
		.ok_or_else(|| {
			(
				StatusCode::UNAUTHORIZED,
				Json(ErrorResponse {
					error: "admin_token not configured on this server".into(),
				}),
			)
		})?;

	let auth_header = headers
		.get(AUTHORIZATION)
		.and_then(|v| v.to_str().ok())
		.ok_or_else(|| {
			(
				StatusCode::UNAUTHORIZED,
				Json(ErrorResponse {
					error: "missing Authorization header".into(),
				}),
			)
		})?;

	let bearer = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
		(
			StatusCode::UNAUTHORIZED,
			Json(ErrorResponse {
				error: "Authorization header must use Bearer scheme".into(),
			}),
		)
	})?;

	if bearer != admin_token {
		return Err((
			StatusCode::FORBIDDEN,
			Json(ErrorResponse {
				error: "invalid admin token".into(),
			}),
		));
	}

	Ok(())
}

// ──────────────────────────── Handlers ────────────────────────────────────────

/// `POST /_admin/v1/vhosts` — Create a new virtual host.
///
/// Request body: `{ "server_name": "qi.agtm.app" }`
/// Response: `{ "server_name": "qi.agtm.app", "verify_key": "ed25519:aBcDe...", "is_bootstrap": false }`
pub(crate) async fn create_vhost(
	State(services): State<crate::State>,
	headers: HeaderMap,
	Json(body): Json<CreateVhostRequest>,
) -> AdminResult<impl IntoResponse> {
	require_admin_token(&services, &headers)?;

	// Validate server_name format
	let server_name: OwnedServerName = body
		.server_name
		.as_str()
		.try_into()
		.map_err(|_e| {
			(
				StatusCode::BAD_REQUEST,
				Json(ErrorResponse {
					error: format!("invalid server_name: {}", body.server_name),
				}),
			)
		})?;

	// Check not already active
	if services.globals.server_is_ours(&server_name) {
		return Err((
			StatusCode::CONFLICT,
			Json(ErrorResponse {
				error: format!("vhost already exists: {server_name}"),
			}),
		));
	}

	// Generate Ed25519 keypair
	let vhost_kp = tuwunel_service::server_keys::keypair::generate_vhost_keypair()
		.map_err(|e| {
			(
				StatusCode::INTERNAL_SERVER_ERROR,
				Json(ErrorResponse {
					error: format!("failed to generate keypair: {e}"),
				}),
			)
		})?;

	// Build the verify_key string before moving vhost_kp
	let verify_key_str = vhost_kp
		.verify_keys
		.iter()
		.next()
		.map(|(id, _key)| id.to_string());

	// Register keypair with server_keys service
	if !services
		.server_keys
		.add_vhost_keypair(server_name.clone(), vhost_kp)
	{
		return Err((
			StatusCode::CONFLICT,
			Json(ErrorResponse {
				error: format!("keypair already registered for vhost: {server_name}"),
			}),
		));
	}

	// Add to VhostRegistry
	services.globals.vhosts.add(server_name.clone());

	Ok((
		StatusCode::CREATED,
		Json(VhostResponse {
			server_name: server_name.to_string(),
			verify_key: verify_key_str,
			is_bootstrap: false,
		}),
	))
}

/// `GET /_admin/v1/vhosts` — List all active virtual hosts.
pub(crate) async fn list_vhosts(
	State(services): State<crate::State>,
	headers: HeaderMap,
) -> AdminResult<Json<ListVhostsResponse>> {
	require_admin_token(&services, &headers)?;

	let bootstrap = services.globals.vhosts.bootstrap_name().clone();
	let all = services.globals.vhosts.list();

	let vhosts = all
		.into_iter()
		.map(|name| {
			let is_bootstrap = name == bootstrap;
			VhostResponse {
				server_name: name.to_string(),
				verify_key: None,
				is_bootstrap,
			}
		})
		.collect();

	Ok(Json(ListVhostsResponse { vhosts }))
}

/// `GET /_admin/v1/vhosts/{name}` — Get details for a specific virtual host.
pub(crate) async fn get_vhost(
	State(services): State<crate::State>,
	headers: HeaderMap,
	Path(name): Path<String>,
) -> AdminResult<Json<VhostResponse>> {
	require_admin_token(&services, &headers)?;

	let server_name: OwnedServerName = name
		.as_str()
		.try_into()
		.map_err(|_e| {
			(
				StatusCode::BAD_REQUEST,
				Json(ErrorResponse {
					error: format!("invalid server_name: {name}"),
				}),
			)
		})?;

	if !services.globals.server_is_ours(&server_name) {
		return Err((
			StatusCode::NOT_FOUND,
			Json(ErrorResponse {
				error: format!("vhost not found: {server_name}"),
			}),
		));
	}

	let bootstrap = services.globals.vhosts.bootstrap_name().clone();
	let is_bootstrap = server_name == bootstrap;

	Ok(Json(VhostResponse {
		server_name: server_name.to_string(),
		verify_key: None,
		is_bootstrap,
	}))
}

/// `DELETE /_admin/v1/vhosts/{name}` — Remove a virtual host.
pub(crate) async fn delete_vhost(
	State(services): State<crate::State>,
	headers: HeaderMap,
	Path(name): Path<String>,
) -> AdminResult<StatusCode> {
	require_admin_token(&services, &headers)?;

	let server_name: OwnedServerName = name
		.as_str()
		.try_into()
		.map_err(|_e| {
			(
				StatusCode::BAD_REQUEST,
				Json(ErrorResponse {
					error: format!("invalid server_name: {name}"),
				}),
			)
		})?;

	if !services.globals.server_is_ours(&server_name) {
		return Err((
			StatusCode::NOT_FOUND,
			Json(ErrorResponse {
				error: format!("vhost not found: {server_name}"),
			}),
		));
	}

	// VhostRegistry.remove() returns false if attempting to remove bootstrap
	if !services.globals.vhosts.remove(&server_name) {
		return Err((
			StatusCode::FORBIDDEN,
			Json(ErrorResponse {
				error: "cannot remove bootstrap vhost".into(),
			}),
		));
	}

	// Also remove the keypair
	services.server_keys.remove_vhost_keypair(&server_name);

	Ok(StatusCode::NO_CONTENT)
}
