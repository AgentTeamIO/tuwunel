mod acquire;
mod get;
mod keypair;
mod request;
mod sign;
mod verify;

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use futures::StreamExt;
use ruma::{
	CanonicalJsonObject, MilliSecondsSinceUnixEpoch, OwnedServerName, OwnedServerSigningKeyId,
	ServerName, ServerSigningKeyId,
	api::federation::discovery::{ServerSigningKeys, VerifyKey},
	room_version_rules::RoomVersionRules,
	serde::Raw,
	signatures::{Ed25519KeyPair, PublicKeyMap, PublicKeySet},
};
use serde_json::value::RawValue as RawJsonValue;
use std::sync::RwLock;
use tuwunel_core::{
	Result, implement,
	utils::{IterStream, timepoint_from_now},
};
use tuwunel_database::{Deserialized, Json, Map};

/// Per-vhost keypair data: version string and the Ed25519 keypair.
pub struct VhostKeypair {
	pub version: String,
	pub keypair: Box<Ed25519KeyPair>,
	pub verify_keys: VerifyKeys,
}

pub struct Service {
	/// Bootstrap keypair (from database, backwards compat)
	keypair: Box<Ed25519KeyPair>,
	verify_keys: VerifyKeys,
	/// Additional vhost keypairs keyed by server name.
	/// The bootstrap server_name is NOT stored here — it uses the fields above.
	vhost_keypairs: RwLock<BTreeMap<OwnedServerName, VhostKeypair>>,
	minimum_valid: Duration,
	services: Arc<crate::services::OnceServices>,
	db: Data,
}

struct Data {
	server_signingkeys: Arc<Map>,
}

pub type VerifyKeys = BTreeMap<OwnedServerSigningKeyId, VerifyKey>;
pub type PubKeyMap = PublicKeyMap;
pub type PubKeys = PublicKeySet;

impl crate::Service for Service {
	fn build(args: &crate::Args<'_>) -> Result<Arc<Self>> {
		let minimum_valid = Duration::from_hours(1);

		let (keypair, verify_keys) = keypair::init(args.db)?;
		debug_assert!(verify_keys.len() == 1, "only one active verify_key supported");

		Ok(Arc::new(Self {
			keypair,
			verify_keys,
			vhost_keypairs: RwLock::new(BTreeMap::new()),
			minimum_valid,
			services: args.services.clone(),
			db: Data {
				server_signingkeys: args.db["server_signingkeys"].clone(),
			},
		}))
	}

	fn name(&self) -> &str { crate::service::make_name(std::module_path!()) }
}

#[implement(Service)]
#[inline]
#[must_use]
pub fn keypair(&self) -> &Ed25519KeyPair { &self.keypair }

#[implement(Service)]
#[inline]
#[must_use]
pub fn active_key_id(&self) -> &ServerSigningKeyId { self.active_verify_key().0 }

#[implement(Service)]
#[inline]
#[must_use]
pub fn active_verify_key(&self) -> (&ServerSigningKeyId, &VerifyKey) {
	debug_assert!(self.verify_keys.len() <= 1, "more than one active verify_key");
	self.verify_keys
		.iter()
		.next()
		.map(|(id, key)| (id.as_ref(), key))
		.expect("missing active verify_key")
}

/// Register a keypair for a virtual host. The keypair is generated in-memory
/// (not persisted to the database — persistence is a later milestone).
/// Returns false if the vhost already has a keypair registered.
#[implement(Service)]
pub fn add_vhost_keypair(&self, server_name: OwnedServerName, vhost_kp: VhostKeypair) -> bool {
	use std::collections::btree_map::Entry;
	let mut map = self
		.vhost_keypairs
		.write()
		.expect("vhost_keypairs lock poisoned");
	match map.entry(server_name) {
		| Entry::Occupied(_) => false,
		| Entry::Vacant(e) => {
			e.insert(vhost_kp);
			true
		},
	}
}

/// Remove a keypair for a virtual host.
#[implement(Service)]
pub fn remove_vhost_keypair(&self, server_name: &ServerName) -> bool {
	let mut map = self
		.vhost_keypairs
		.write()
		.expect("vhost_keypairs lock poisoned");
	map.remove(server_name).is_some()
}

/// Get the keypair for a given server name. Returns the bootstrap keypair
/// if the server name matches the bootstrap, otherwise looks up vhost keypairs.
///
/// Returns None if the server name is not known. The caller receives a clone
/// of the Arc-wrapped Ed25519KeyPair to avoid holding the RwLock across await points.
///
/// Note: For the bootstrap keypair, we return a reference to self.keypair via a
/// different code path in sign.rs. This method is primarily for vhost lookups.
#[implement(Service)]
#[must_use]
pub fn is_vhost(&self, server_name: &ServerName) -> bool {
	let map = self
		.vhost_keypairs
		.read()
		.expect("vhost_keypairs lock poisoned");
	map.contains_key(server_name)
}

#[implement(Service)]
async fn add_signing_keys(&self, new_keys: ServerSigningKeys) {
	let origin = &new_keys.server_name;

	// (timo) Not atomic, but this is not critical
	let mut keys: ServerSigningKeys = self
		.db
		.server_signingkeys
		.get(origin)
		.await
		.deserialized()
		.unwrap_or_else(|_| {
			// Just insert "now", it doesn't matter
			ServerSigningKeys::new(origin.to_owned(), MilliSecondsSinceUnixEpoch::now())
		});

	keys.verify_keys.extend(new_keys.verify_keys);
	keys.old_verify_keys
		.extend(new_keys.old_verify_keys);

	self.db
		.server_signingkeys
		.raw_put(origin, Json(&keys));
}

#[implement(Service)]
pub async fn required_keys_exist(
	&self,
	object: &CanonicalJsonObject,
	rules: &RoomVersionRules,
) -> bool {
	use ruma::signatures::required_keys;

	let Ok(required_keys) = required_keys(object, &rules.signatures) else {
		return false;
	};

	required_keys
		.iter()
		.flat_map(|(server, key_ids)| key_ids.iter().map(move |key_id| (server, key_id)))
		.stream()
		.all(|(server, key_id)| self.verify_key_exists(server, key_id))
		.await
}

#[implement(Service)]
pub async fn verify_key_exists(&self, origin: &ServerName, key_id: &ServerSigningKeyId) -> bool {
	type KeysMap<'a> = BTreeMap<&'a ServerSigningKeyId, &'a RawJsonValue>;

	let Ok(keys) = self
		.db
		.server_signingkeys
		.get(origin)
		.await
		.deserialized::<Raw<ServerSigningKeys>>()
	else {
		return false;
	};

	if let Ok(Some(verify_keys)) = keys.get_field::<KeysMap<'_>>("verify_keys")
		&& verify_keys.contains_key(key_id)
	{
		return true;
	}

	if let Ok(Some(old_verify_keys)) = keys.get_field::<KeysMap<'_>>("old_verify_keys")
		&& old_verify_keys.contains_key(key_id)
	{
		return true;
	}

	false
}

#[implement(Service)]
pub async fn verify_keys_for(&self, origin: &ServerName) -> VerifyKeys {
	let mut keys = self
		.signing_keys_for(origin)
		.await
		.map(|keys| merge_old_keys(keys).verify_keys)
		.unwrap_or(BTreeMap::new());

	if self.services.globals.server_is_ours(origin) {
		// Check if this is the bootstrap server or a vhost
		if origin == self.services.globals.server_name() {
			keys.extend(self.verify_keys.clone());
		} else if let Some(vhost_keys) = self.vhost_verify_keys(origin) {
			keys.extend(vhost_keys);
		}
	}

	keys
}

/// Get verify keys for a vhost, if it exists.
#[implement(Service)]
#[must_use]
fn vhost_verify_keys(&self, origin: &ServerName) -> Option<VerifyKeys> {
	let map = self
		.vhost_keypairs
		.read()
		.expect("vhost_keypairs lock poisoned");
	map.get(origin).map(|vkp| vkp.verify_keys.clone())
}

#[implement(Service)]
pub async fn signing_keys_for(&self, origin: &ServerName) -> Result<ServerSigningKeys> {
	self.db
		.server_signingkeys
		.get(origin)
		.await
		.deserialized()
}

#[implement(Service)]
fn minimum_valid_ts(&self) -> MilliSecondsSinceUnixEpoch {
	let timepoint =
		timepoint_from_now(self.minimum_valid).expect("SystemTime should not overflow");

	MilliSecondsSinceUnixEpoch::from_system_time(timepoint).expect("UInt should not overflow")
}

fn merge_old_keys(mut keys: ServerSigningKeys) -> ServerSigningKeys {
	keys.verify_keys.extend(
		keys.old_verify_keys
			.clone()
			.into_iter()
			.map(|(key_id, old)| (key_id, VerifyKey::new(old.key))),
	);

	keys
}

fn extract_key(mut keys: ServerSigningKeys, key_id: &ServerSigningKeyId) -> Option<VerifyKey> {
	keys.verify_keys.remove(key_id).or_else(|| {
		keys.old_verify_keys
			.remove(key_id)
			.map(|old| VerifyKey::new(old.key))
	})
}

fn key_exists(keys: &ServerSigningKeys, key_id: &ServerSigningKeyId) -> bool {
	keys.verify_keys.contains_key(key_id) || keys.old_verify_keys.contains_key(key_id)
}
