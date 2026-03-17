//! NatsWatcher — watches the NATS `kv_vhosts` bucket for dynamic vhost provisioning.
//!
//! On startup:
//! 1. Connect to NATS
//! 2. Subscribe to watch_all() on the kv_vhosts bucket (replays all current values)
//! 3. Consume the watch stream for live updates
//!
//! Operations:
//! - Put with status=Provisioning → load keypair, add to VhostRegistry, CAS to Active
//! - Put with status=Active → ensure loaded (idempotent)
//! - Put with status=Suspended|Archived → remove from VhostRegistry
//! - Delete → remove from VhostRegistry

use std::{sync::Arc, time::Duration};

use async_nats::jetstream;
use base64::Engine as _;
use futures::StreamExt;
use ruma::{
	OwnedServerName,
	api::federation::discovery::VerifyKey,
	serde::Base64,
	signatures::Ed25519KeyPair,
};
use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use tuwunel_core::{debug, debug_info, error, info, warn};

use crate::Services;

/// Mirror of the VhostEntry type from agentteam-core.
/// Kept in sync manually since Tuwunel is a separate workspace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VhostEntry {
	pub server_name: String,
	pub status: VhostStatus,
	/// Base64-encoded DER bytes of the Ed25519 signing key.
	pub signing_key_bytes: String,
	/// Key version string (e.g. "aBcDeFgH").
	pub signing_key_version: String,
	/// Zitadel organization ID that owns this vhost.
	pub org_id: String,
	/// Unix milliseconds timestamp of creation.
	pub created_at: u64,
	/// Unix milliseconds timestamp of last update.
	pub updated_at: u64,
}

/// Mirror of VhostStatus from agentteam-core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VhostStatus {
	Provisioning,
	Active,
	Suspended,
	Archived,
}

const KV_VHOSTS_BUCKET: &str = "kv_vhosts";
const RECONNECT_DELAY: Duration = Duration::from_secs(5);

/// Spawn the NatsWatcher background task.
/// Returns the JoinHandle so the caller can manage the task's lifecycle.
pub fn spawn(services: Arc<Services>) -> tokio::task::JoinHandle<()> {
	let nats_url = services
		.server
		.config
		.nats_url
		.clone()
		.expect("nats_url must be set to spawn NatsWatcher");

	tokio::spawn(async move {
		run_loop(&nats_url, &services).await;
	})
}

/// Main reconnect loop. If NATS is unavailable or the connection drops,
/// retry after a delay. Never panic — graceful degradation.
async fn run_loop(nats_url: &str, services: &Arc<Services>) {
	loop {
		match run_once(nats_url, services).await {
			| Ok(()) => {
				info!("NatsWatcher finished cleanly");
				return;
			},
			| Err(e) => {
				warn!("NatsWatcher error: {e:#}. Reconnecting in {RECONNECT_DELAY:?}...");
				sleep(RECONNECT_DELAY).await;

				// If server is shutting down, exit the loop
				if !services.server.running() {
					debug!("NatsWatcher stopping — server is shutting down");
					return;
				}
			},
		}
	}
}

/// A single run: connect → watch → full scan → consume stream.
async fn run_once(nats_url: &str, services: &Arc<Services>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
	info!("NatsWatcher connecting to NATS at {nats_url}...");

	let client = async_nats::connect(nats_url).await?;
	let js = jetstream::new(client);

	info!("NatsWatcher connected. Opening kv_vhosts bucket...");

	let kv = js.get_key_value(KV_VHOSTS_BUCKET).await?;

	// watch_all() replays all current values (DeliverLastPerSubjectPolicy)
	// before delivering live updates, so a separate full_scan is unnecessary.
	let mut watcher = kv.watch_all().await?;

	info!("NatsWatcher watching for updates (initial replay + live)...");
	while let Some(entry) = watcher.next().await {
		// Check if server is shutting down
		if !services.server.running() {
			debug!("NatsWatcher stopping — server is shutting down");
			break;
		}

		match entry {
			| Ok(entry) => {
				handle_kv_entry(&kv, &entry, services).await;
			},
			| Err(e) => {
				error!("NatsWatcher watch error: {e}");
				// Return error to trigger reconnect
				return Err(Box::new(e));
			},
		}
	}

	// Stream ended — NATS disconnected. Return error to trigger reconnect.
	Err("NATS watcher stream closed unexpectedly".into())
}

/// Full scan: iterate all keys in the bucket and process each entry.
/// Retained for manual recovery; not called during normal startup since
/// watch_all() already replays all current values.
#[allow(dead_code)]
async fn full_scan(
	kv: &jetstream::kv::Store,
	services: &Arc<Services>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
	// keys() returns all keys; we fetch each value individually
	let keys: Vec<String> = {
		let mut key_list = Vec::new();
		let mut keys_stream = kv.keys().await?;
		while let Some(key) = keys_stream.next().await {
			match key {
				| Ok(k) => key_list.push(k),
				| Err(e) => {
					warn!("NatsWatcher: error reading key during scan: {e}");
				},
			}
		}
		key_list
	};

	debug_info!("NatsWatcher full scan: found {} vhost entries", keys.len());

	for key in &keys {
		match kv.entry(key).await {
			| Ok(Some(entry)) => {
				handle_kv_entry(kv, &entry, services).await;
			},
			| Ok(None) => {
				debug!("NatsWatcher: key {key} disappeared during scan");
			},
			| Err(e) => {
				warn!("NatsWatcher: error fetching key {key}: {e}");
			},
		}
	}

	debug_info!("NatsWatcher full scan complete");
	Ok(())
}

/// Handle a single KV entry (from watch or scan).
async fn handle_kv_entry(
	kv: &jetstream::kv::Store,
	entry: &jetstream::kv::Entry,
	services: &Arc<Services>,
) {
	use async_nats::jetstream::kv::Operation;

	match entry.operation {
		| Operation::Put => {
			handle_put(kv, entry, services).await;
		},
		| Operation::Delete | Operation::Purge => {
			handle_delete(entry, services);
		},
	}
}

/// Handle a Put operation on a vhost entry.
async fn handle_put(
	kv: &jetstream::kv::Store,
	entry: &jetstream::kv::Entry,
	services: &Arc<Services>,
) {
	let key = &entry.key;
	let value = &entry.value;

	let vhost: VhostEntry = match serde_json::from_slice(value) {
		| Ok(v) => v,
		| Err(e) => {
			warn!("NatsWatcher: failed to parse VhostEntry for key {key}: {e}");
			return;
		},
	};

	match vhost.status {
		| VhostStatus::Provisioning => {
			debug_info!("NatsWatcher: provisioning vhost {}", vhost.server_name);
			if let Err(e) = provision_vhost(kv, entry, &vhost, services).await {
				error!(
					"NatsWatcher: failed to provision vhost {}: {e}",
					vhost.server_name
				);
			}
		},
		| VhostStatus::Active => {
			// Idempotent: ensure the vhost is loaded
			ensure_loaded(&vhost, services);
		},
		| VhostStatus::Suspended | VhostStatus::Archived => {
			debug_info!(
				"NatsWatcher: removing vhost {} (status={:?})",
				vhost.server_name,
				vhost.status
			);
			remove_vhost(&vhost, services);
		},
	}
}

/// Handle a Delete operation — remove the vhost from the registry.
fn handle_delete(entry: &jetstream::kv::Entry, services: &Arc<Services>) {
	let key = &entry.key;
	debug_info!("NatsWatcher: vhost key {key} deleted, removing from registry");

	// The key is the server_name
	let server_name: OwnedServerName = match key.as_str().try_into() {
		| Ok(sn) => sn,
		| Err(e) => {
			warn!("NatsWatcher: invalid server_name in deleted key {key}: {e}");
			return;
		},
	};

	services.globals.vhosts.remove(&server_name);
	services.server_keys.remove_vhost_keypair(&server_name);
	debug!("NatsWatcher: removed vhost {server_name}");
}

/// Provision a new vhost: decode keypair, add to server_keys and VhostRegistry,
/// then CAS update the status from Provisioning to Active.
async fn provision_vhost(
	kv: &jetstream::kv::Store,
	entry: &jetstream::kv::Entry,
	vhost: &VhostEntry,
	services: &Arc<Services>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
	let server_name: OwnedServerName = vhost.server_name.as_str().try_into()?;

	// Decode the signing key DER bytes from base64
	let der_bytes = base64::engine::general_purpose::STANDARD.decode(&vhost.signing_key_bytes)?;

	// Create the Ed25519KeyPair from DER bytes + version
	let keypair = Ed25519KeyPair::from_der(&der_bytes, vhost.signing_key_version.clone())
		.map_err(|e| format!("Ed25519KeyPair::from_der failed: {e:?}"))?;

	// Build verify keys
	let verify_key = VerifyKey {
		key: Base64::new(keypair.public_key().to_vec()),
	};

	let key_id_str = format!("ed25519:{}", vhost.signing_key_version);
	let key_id = key_id_str
		.try_into()
		.map_err(|e| format!("invalid key ID: {e}"))?;
	let verify_keys = [(key_id, verify_key)].into();

	let vhost_kp = crate::server_keys::VhostKeypair {
		version: vhost.signing_key_version.clone(),
		keypair: Box::new(keypair),
		verify_keys,
		der: der_bytes,
	};

	// Add keypair to server_keys service (also persists to DB)
	services
		.server_keys
		.add_vhost_keypair(server_name.clone(), vhost_kp);

	// Add to VhostRegistry
	services.globals.vhosts.add(server_name.clone());

	info!("NatsWatcher: vhost {server_name} provisioned successfully");

	// CAS update status from Provisioning to Active
	// Use entry.revision for compare-and-swap
	let mut updated = vhost.clone();
	updated.status = VhostStatus::Active;
	updated.updated_at = now_millis();

	let new_value = serde_json::to_vec(&updated)?;

	match kv.update(&entry.key, new_value.into(), entry.revision).await {
		| Ok(new_revision) => {
			debug_info!(
				"NatsWatcher: CAS updated vhost {} to Active (revision {new_revision})",
				vhost.server_name
			);
		},
		| Err(e) => {
			// CAS failure is expected and safe — another process may have already updated
			debug!(
				"NatsWatcher: CAS update for vhost {} failed (expected if racing): {e}",
				vhost.server_name
			);
		},
	}

	Ok(())
}

/// Ensure a vhost is loaded in the registry and server_keys (idempotent for Active status).
fn ensure_loaded(vhost: &VhostEntry, services: &Arc<Services>) {
	let server_name: OwnedServerName = match vhost.server_name.as_str().try_into() {
		| Ok(sn) => sn,
		| Err(e) => {
			warn!(
				"NatsWatcher: invalid server_name for active vhost {}: {e}",
				vhost.server_name
			);
			return;
		},
	};

	// Already in registry?
	if services.globals.server_is_ours(&server_name)
		&& services.server_keys.is_vhost(&server_name)
	{
		return;
	}

	// Need to load the keypair
	let der_bytes = match base64::engine::general_purpose::STANDARD.decode(&vhost.signing_key_bytes)
	{
		| Ok(b) => b,
		| Err(e) => {
			warn!(
				"NatsWatcher: failed to decode signing_key_bytes for {}: {e}",
				vhost.server_name
			);
			return;
		},
	};

	let keypair =
		match Ed25519KeyPair::from_der(&der_bytes, vhost.signing_key_version.clone()) {
			| Ok(kp) => kp,
			| Err(e) => {
				warn!(
					"NatsWatcher: failed to load keypair for {}: {e:?}",
					vhost.server_name
				);
				return;
			},
		};

	let verify_key = VerifyKey {
		key: Base64::new(keypair.public_key().to_vec()),
	};

	let key_id_str = format!("ed25519:{}", vhost.signing_key_version);
	let key_id = match key_id_str.try_into() {
		| Ok(kid) => kid,
		| Err(e) => {
			warn!(
				"NatsWatcher: invalid key ID for {}: {e}",
				vhost.server_name
			);
			return;
		},
	};
	let verify_keys = [(key_id, verify_key)].into();

	let vhost_kp = crate::server_keys::VhostKeypair {
		version: vhost.signing_key_version.clone(),
		keypair: Box::new(keypair),
		verify_keys,
		der: der_bytes,
	};

	services
		.server_keys
		.add_vhost_keypair(server_name.clone(), vhost_kp);
	services.globals.vhosts.add(server_name.clone());

	debug_info!("NatsWatcher: loaded active vhost {server_name}");
}

/// Remove a vhost from the registry and server_keys.
fn remove_vhost(vhost: &VhostEntry, services: &Arc<Services>) {
	let server_name: OwnedServerName = match vhost.server_name.as_str().try_into() {
		| Ok(sn) => sn,
		| Err(e) => {
			warn!(
				"NatsWatcher: invalid server_name for removal {}: {e}",
				vhost.server_name
			);
			return;
		},
	};

	services.globals.vhosts.remove(&server_name);
	services.server_keys.remove_vhost_keypair(&server_name);
	debug!("NatsWatcher: removed vhost {server_name}");
}

/// Get current Unix timestamp in milliseconds.
fn now_millis() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap_or_default()
		.as_millis() as u64
}
