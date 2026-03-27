use axum::extract::State;
use http::HeaderMap;
use ruma::{
	OwnedServerName, ServerName,
	api::{client::error::ErrorKind, federation::discovery::discover_homeserver},
};
use tuwunel_core::{Error, Result};

use crate::Ruma;

/// # `GET /.well-known/matrix/server`
///
/// Returns the .well-known URL for federation delegation.
/// With vhost support, dynamically derives the server from the Host header
/// when the host matches a known vhost (e.g. `qi.agtm.app` → `qi.agtm.app:443`).
/// Falls back to the static config `well_known.server` for the bootstrap server.
pub(crate) async fn well_known_server(
	State(services): State<crate::State>,
	headers: HeaderMap,
	_body: Ruma<discover_homeserver::Request>,
) -> Result<discover_homeserver::Response> {
	// Check vhost first: if Host matches a known vhost, return dynamic delegation
	if let Some(server) = vhost_server(&services, &headers) {
		return Ok(discover_homeserver::Response { server });
	}

	// Fall back to static config for bootstrap server
	Ok(discover_homeserver::Response {
		server: match services.server.config.well_known.server.as_ref() {
			| Some(server_name) => server_name.to_owned(),
			| None => return Err(Error::BadRequest(ErrorKind::NotFound, "Not found.")),
		},
	})
}

/// Derive federation delegation from the Host header for known vhosts.
/// Returns `Some(OwnedServerName)` with port 443 for recognised vhosts,
/// `None` otherwise.
fn vhost_server(
	services: &tuwunel_service::Services,
	headers: &HeaderMap,
) -> Option<OwnedServerName> {
	let host = headers.get(http::header::HOST)?;
	let host_str = host.to_str().ok()?;
	let name = host_str.split(':').next().unwrap_or(host_str);
	let sn = <&ServerName>::try_from(name).ok()?;

	// Only generate dynamic delegation for vhosts, not the bootstrap server
	if sn != services.globals.server_name() && services.globals.server_is_ours(sn) {
		let delegation = format!("{name}:443");
		<&ServerName>::try_from(delegation.as_str())
			.map(|s| s.to_owned())
			.ok()
	} else {
		None
	}
}
