use std::{collections::BTreeMap, sync::Arc};

use ruma::{
	OwnedServerName, ServerName,
	api::federation::discovery::VerifyKey, serde::Base64, signatures::Ed25519KeyPair,
};
use tuwunel_core::{Result, debug, debug_info, err, error, utils, utils::string_from_bytes, warn};
use tuwunel_database::{Database, Map};

use super::VerifyKeys;

pub(super) fn init(db: &Arc<Database>) -> Result<(Box<Ed25519KeyPair>, VerifyKeys)> {
	let keypair = load(db).inspect_err(|_e| {
		error!("Keypair invalid. Deleting...");
		remove(db);
	})?;

	let verify_key = VerifyKey {
		key: Base64::new(keypair.public_key().to_vec()),
	};

	let id = format!("ed25519:{}", keypair.version());
	let verify_keys: VerifyKeys = [(id.try_into()?, verify_key)].into();

	Ok((keypair, verify_keys))
}

fn load(db: &Arc<Database>) -> Result<Box<Ed25519KeyPair>> {
	let (version, key) = db["global"]
		.get_blocking(b"keypair")
		.map(|ref val| {
			// database deserializer is having trouble with this so it's manual for now
			let mut elems = val.split(|&b| b == b'\xFF');
			let vlen = elems.next().expect("invalid keypair entry").len();
			let ver = string_from_bytes(&val[..vlen]).expect("invalid keypair version");
			let der = val[vlen.saturating_add(1)..].to_vec();
			debug!("Found existing Ed25519 keypair: {ver:?}");
			(ver, der)
		})
		.or_else(|e| {
			assert!(e.is_not_found(), "unexpected error fetching keypair");
			create(db)
		})?;

	let key = Ed25519KeyPair::from_der(&key, version)
		.map_err(|e| err!("Failed to load ed25519 keypair from der: {e:?}"))?;

	Ok(Box::new(key))
}

fn create(db: &Arc<Database>) -> Result<(String, Vec<u8>)> {
	let keypair = Ed25519KeyPair::generate()
		.map_err(|e| err!("Failed to generate new ed25519 keypair: {e:?}"))?;

	let id = utils::rand::string(8);
	debug_info!("Generated new Ed25519 keypair: {id:?}");

	let value: (String, Vec<u8>) = (id, keypair.to_vec());
	db["global"].raw_put(b"keypair", &value);

	Ok(value)
}

#[inline]
fn remove(db: &Arc<Database>) {
	let global = &db["global"];
	global.remove(b"keypair");
}

/// Generate a new keypair for a virtual host.
/// Returns a `VhostKeypair` containing the version, keypair, verify keys, and raw DER bytes.
///
/// Used by admin API to register new vhosts.
pub fn generate_vhost_keypair() -> Result<super::VhostKeypair> {
	let raw_keypair = Ed25519KeyPair::generate()
		.map_err(|e| err!("Failed to generate vhost ed25519 keypair: {e:?}"))?;

	let version = utils::rand::string(8);
	let der = raw_keypair.to_vec();

	let keypair = Ed25519KeyPair::from_der(&der, version.clone())
		.map_err(|e| err!("Failed to load vhost ed25519 keypair from der: {e:?}"))?;

	let verify_key = VerifyKey {
		key: Base64::new(keypair.public_key().to_vec()),
	};

	let id = format!("ed25519:{version}");
	let verify_keys: VerifyKeys = [(id.try_into()?, verify_key)].into();

	Ok(super::VhostKeypair {
		version,
		keypair: Box::new(keypair),
		verify_keys,
		der,
	})
}

// ──────────────────────────── Vhost persistence ──────────────────────────────

/// DB key for the list of vhost server names (stored as serialized Vec<String>).
const VHOST_NAMES_KEY: &[u8] = b"vhost_names";

/// DB key prefix for individual vhost keypairs.
const VHOST_KEYPAIR_PREFIX: &str = "vhost_keypair:";

/// Build the database key for a vhost keypair: `vhost_keypair:{server_name}`.
fn vhost_db_key(server_name: &ServerName) -> Vec<u8> {
	let mut key = VHOST_KEYPAIR_PREFIX.as_bytes().to_vec();
	key.extend_from_slice(server_name.as_bytes());
	key
}

/// Persist a vhost keypair to the `global` database tree and update the names index.
pub(super) fn save_vhost_keypair(
	global: &Arc<Map>,
	server_name: &ServerName,
	version: &str,
	der_bytes: &[u8],
) {
	// Store the keypair data
	let key = vhost_db_key(server_name);
	let value: (String, Vec<u8>) = (version.to_owned(), der_bytes.to_vec());
	global.raw_put(&key, &value);

	// Update the names index
	let mut names = load_vhost_names(global);
	let name_str = server_name.to_string();
	if !names.contains(&name_str) {
		names.push(name_str);
		global.raw_put(VHOST_NAMES_KEY, &names);
	}

	debug!("Persisted vhost keypair for {server_name}");
}

/// Delete a vhost keypair from the `global` database tree and update the names index.
pub(super) fn delete_vhost_keypair(global: &Arc<Map>, server_name: &ServerName) {
	// Remove the keypair data
	let key = vhost_db_key(server_name);
	global.remove(&key);

	// Update the names index
	let mut names = load_vhost_names(global);
	let name_str = server_name.to_string();
	names.retain(|n| n != &name_str);
	global.raw_put(VHOST_NAMES_KEY, &names);

	debug!("Deleted persisted vhost keypair for {server_name}");
}

/// Load the list of vhost server names from the names index.
fn load_vhost_names(global: &Arc<Map>) -> Vec<String> {
	use tuwunel_database::Deserialized;

	global
		.get_blocking(VHOST_NAMES_KEY)
		.deserialized::<Vec<String>>()
		.unwrap_or_default()
}

/// Load all persisted vhost keypairs from the `global` database tree.
/// Returns a BTreeMap keyed by server name, suitable for populating `vhost_keypairs`.
pub(super) fn load_all_vhost_keypairs(
	db: &Arc<Database>,
) -> BTreeMap<OwnedServerName, super::VhostKeypair> {
	use tuwunel_database::Deserialized;

	let global = &db["global"];
	let mut result = BTreeMap::new();

	// Load the names index to know which vhosts to restore
	let names = load_vhost_names(&global);
	for name_str in &names {
		let server_name: OwnedServerName = match name_str.as_str().try_into() {
			| Ok(sn) => sn,
			| Err(e) => {
				warn!("Invalid server name in vhost_names index {name_str:?}: {e}");
				continue;
			},
		};

		let key = vhost_db_key(&server_name);
		let (version, der): (String, Vec<u8>) = match global
			.get_blocking(&key)
			.deserialized::<(String, Vec<u8>)>()
		{
			| Ok(v) => v,
			| Err(e) => {
				warn!("Failed to load vhost keypair for {server_name}: {e}");
				continue;
			},
		};

		let keypair = match Ed25519KeyPair::from_der(&der, version.clone()) {
			| Ok(kp) => kp,
			| Err(e) => {
				warn!("Failed to restore vhost keypair for {server_name}: {e:?}");
				continue;
			},
		};

		let verify_key = VerifyKey {
			key: Base64::new(keypair.public_key().to_vec()),
		};

		let id = format!("ed25519:{version}");
		let key_id = match id.try_into() {
			| Ok(kid) => kid,
			| Err(e) => {
				warn!("Invalid key ID for vhost {server_name}: {e}");
				continue;
			},
		};
		let verify_keys: VerifyKeys = [(key_id, verify_key)].into();

		debug!("Loaded persisted vhost keypair for {server_name} (version={version})");
		result.insert(server_name, super::VhostKeypair {
			version,
			keypair: Box::new(keypair),
			verify_keys,
			der,
		});
	}

	if !result.is_empty() {
		debug_info!("Loaded {} vhost keypair(s) from database", result.len());
	}

	result
}
