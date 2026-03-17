use std::{
	mem::take,
	time::{Duration, SystemTime},
};

use axum::{Json, extract::State, response::IntoResponse};
use http::HeaderMap;
use ruma::{
	CanonicalJsonObject, MilliSecondsSinceUnixEpoch, OwnedServerName, OwnedServerSigningKeyId,
	ServerName, Signatures,
	api::{
		OutgoingResponse,
		federation::discovery::{OldVerifyKey, ServerSigningKeys, VerifyKey, get_server_keys},
	},
	serde::Raw,
};
use tuwunel_core::{Err, Result, utils::timepoint_from_now};

/// # `GET /_matrix/key/v2/server`
///
/// Gets the public signing keys of this server.
///
/// With vhost support, the Host header is used to determine which vhost's
/// keys to return. If the Host header is missing or does not match any known
/// vhost (including bootstrap), returns 404. This is critical for federation
/// correctness — returning bootstrap keys for an unknown host would let
/// remote servers accept forged events.
///
/// - Matrix does not support invalidating public keys, so the key returned by
///   this will be valid forever.
// Response type for this endpoint is Json because we need to calculate a
// signature for the response
pub(crate) async fn get_server_keys_route(
	State(services): State<crate::State>,
	headers: HeaderMap,
) -> Result<impl IntoResponse> {
	// Extract vhost from Host header — no fallback to bootstrap.
	// Returning bootstrap keys for an unrecognised host would let remote
	// servers accept events signed by the bootstrap key as if they came from
	// the vhost, breaking federation integrity.
	let Some(server_name) = resolve_server_name(&services, &headers) else {
		return Err!(Request(NotFound("Unknown server name")));
	};

	let mut all_keys = services
		.server_keys
		.verify_keys_for(&server_name)
		.await;

	// For bootstrap server, use the known active key id.
	// For vhosts, pick the first (and typically only) key.
	let verify_keys = if server_name == services.globals.server_name() {
		let active_key_id = services.server_keys.active_key_id();
		all_keys
			.remove_entry(active_key_id)
			.expect("active verify_key is missing")
	} else {
		// Vhost: take the first key (vhosts have exactly one active key)
		let first_key = all_keys.keys().next().cloned();
		match first_key {
			| Some(key_id) => all_keys.remove_entry(&key_id).expect("key must exist"),
			| None => {
				// No keys found for this vhost — return 404 instead of silently
				// falling back to bootstrap keys
				return Err!(Request(NotFound("No keys found for this server")));
			},
		}
	};

	build_response(&services, &server_name, verify_keys, all_keys)
}

/// Build the signed JSON response for server keys.
fn build_response(
	services: &tuwunel_service::Services,
	server_name: &ServerName,
	verify_keys: (OwnedServerSigningKeyId, VerifyKey),
	old_keys: std::collections::BTreeMap<OwnedServerSigningKeyId, VerifyKey>,
) -> Result<Json<CanonicalJsonObject>> {
	let old_verify_keys = old_keys
		.into_iter()
		.map(|(id, key)| (id, OldVerifyKey::new(expires_ts(), key.key)))
		.collect();

	let server_key = ServerSigningKeys {
		verify_keys: [verify_keys].into(),
		old_verify_keys,
		server_name: server_name.to_owned(),
		valid_until_ts: valid_until_ts(),
		signatures: Signatures::new(),
	};

	let server_key = Raw::new(&server_key)?;
	let mut response = get_server_keys::v2::Response::new(server_key)
		.try_into_http_response::<Vec<u8>>()
		.map(|mut response| take(response.body_mut()))
		.and_then(|body| serde_json::from_slice(&body).map_err(Into::into))?;

	// Sign with the correct vhost keypair
	services
		.server_keys
		.sign_json_for_vhost(&mut response, server_name)?;

	Ok(Json(response))
}

/// Resolve the server name from the Host header.
/// Returns `Some(name)` if the Host matches the bootstrap server or a known
/// vhost, `None` otherwise. No fallback — callers decide what to do when the
/// host is unrecognised.
fn resolve_server_name(
	services: &tuwunel_service::Services,
	headers: &HeaderMap,
) -> Option<OwnedServerName> {
	let host = headers.get(http::header::HOST)?;
	let host_str = host.to_str().ok()?;

	// Strip port if present (e.g. "example.com:8448" -> "example.com")
	let name = host_str.split(':').next().unwrap_or(host_str);
	let sn = <&ServerName>::try_from(name).ok()?;

	if services.globals.server_is_ours(sn) {
		Some(sn.to_owned())
	} else {
		None
	}
}

fn valid_until_ts() -> MilliSecondsSinceUnixEpoch {
	let dur = Duration::from_hours(168);
	let timepoint = timepoint_from_now(dur).expect("SystemTime should not overflow");
	MilliSecondsSinceUnixEpoch::from_system_time(timepoint).expect("UInt should not overflow")
}

fn expires_ts() -> MilliSecondsSinceUnixEpoch {
	let timepoint = SystemTime::now();
	MilliSecondsSinceUnixEpoch::from_system_time(timepoint).expect("UInt should not overflow")
}

/// # `GET /_matrix/key/v2/server/{keyId}`
///
/// Gets the public signing keys of this server.
///
/// - Matrix does not support invalidating public keys, so the key returned by
///   this will be valid forever.
pub(crate) async fn get_server_keys_deprecated_route(
	State(services): State<crate::State>,
	headers: HeaderMap,
) -> impl IntoResponse {
	get_server_keys_route(State(services), headers).await
}
