use ruma::{CanonicalJsonObject, CanonicalJsonValue, OwnedEventId, RoomVersionId, ServerName};
use tuwunel_core::{
	Result, err, implement,
	matrix::{event::gen_event_id, room_version},
};

#[implement(super::Service)]
pub fn gen_id_hash_and_sign_event(
	&self,
	object: &mut CanonicalJsonObject,
	room_version_id: &RoomVersionId,
) -> Result<OwnedEventId> {
	self.gen_id_hash_and_sign_event_for_vhost(
		object,
		room_version_id,
		self.services.globals.server_name(),
	)
}

/// Generate event ID, hash, and sign using the specified vhost's keypair.
/// Falls back to bootstrap keypair if the server name matches bootstrap.
#[implement(super::Service)]
pub fn gen_id_hash_and_sign_event_for_vhost(
	&self,
	object: &mut CanonicalJsonObject,
	room_version_id: &RoomVersionId,
	server_name: &ServerName,
) -> Result<OwnedEventId> {
	object.remove("event_id");

	if room_version::rules(room_version_id)?
		.event_format
		.require_event_id
	{
		self.gen_id_hash_and_sign_event_v1(object, room_version_id, server_name)
	} else {
		self.gen_id_hash_and_sign_event_v3(object, room_version_id, server_name)
	}
}

#[implement(super::Service)]
fn gen_id_hash_and_sign_event_v1(
	&self,
	object: &mut CanonicalJsonObject,
	room_version_id: &RoomVersionId,
	server_name: &ServerName,
) -> Result<OwnedEventId> {
	let event_id = gen_event_id(object, room_version_id)?;

	object.insert("event_id".into(), CanonicalJsonValue::String(event_id.clone().into()));

	self.services
		.server_keys
		.hash_and_sign_event_for_vhost(object, room_version_id, server_name)?;

	Ok(event_id)
}

#[implement(super::Service)]
fn gen_id_hash_and_sign_event_v3(
	&self,
	object: &mut CanonicalJsonObject,
	room_version_id: &RoomVersionId,
	server_name: &ServerName,
) -> Result<OwnedEventId> {
	self.services
		.server_keys
		.hash_and_sign_event_for_vhost(object, room_version_id, server_name)?;

	let event_id = gen_event_id(object, room_version_id)?;

	object.insert("event_id".into(), CanonicalJsonValue::String(event_id.clone().into()));

	Ok(event_id)
}

/// Hash and sign an event using the bootstrap keypair.
/// This is the backwards-compatible path used by all existing code.
#[implement(super::Service)]
pub fn hash_and_sign_event(
	&self,
	object: &mut CanonicalJsonObject,
	room_version_id: &RoomVersionId,
) -> Result {
	use ruma::signatures::hash_and_sign_event;

	let server_name = &self.services.server.name;
	let room_version_rules = room_version::rules(room_version_id)?;

	hash_and_sign_event(
		server_name.as_str(),
		self.keypair(),
		object,
		&room_version_rules.redaction,
	)
	.map_err(|e| {
		use ruma::signatures::Error::PduSize;
		match e {
			| PduSize => {
				err!(Request(TooLarge("PDU exceeds 65535 bytes")))
			},
			| _ => err!(Request(Unknown(warn!("Signing event failed: {e}")))),
		}
	})
}

/// Hash and sign an event for a specific vhost.
/// Falls back to bootstrap keypair if the server name matches bootstrap.
/// Returns an error if the server name is not known (neither bootstrap nor registered vhost).
#[implement(super::Service)]
pub fn hash_and_sign_event_for_vhost(
	&self,
	object: &mut CanonicalJsonObject,
	room_version_id: &RoomVersionId,
	server_name: &ServerName,
) -> Result {
	use ruma::signatures::hash_and_sign_event;

	let room_version_rules = room_version::rules(room_version_id)?;

	// Bootstrap server uses the primary keypair
	if server_name == self.services.globals.server_name() {
		return hash_and_sign_event(
			server_name.as_str(),
			self.keypair(),
			object,
			&room_version_rules.redaction,
		)
		.map_err(|e| {
			use ruma::signatures::Error::PduSize;
			match e {
				| PduSize => {
					err!(Request(TooLarge("PDU exceeds 65535 bytes")))
				},
				| _ => err!(Request(Unknown(warn!("Signing event for vhost failed: {e}")))),
			}
		});
	}

	// Look up vhost keypair
	let map = self
		.vhost_keypairs
		.read()
		.expect("vhost_keypairs lock poisoned");

	let vhost_kp = map
		.get(server_name)
		.ok_or_else(|| err!(Request(Unknown("Unknown vhost: {server_name}"))))?;

	hash_and_sign_event(
		server_name.as_str(),
		&*vhost_kp.keypair,
		object,
		&room_version_rules.redaction,
	)
	.map_err(|e| {
		use ruma::signatures::Error::PduSize;
		match e {
			| PduSize => {
				err!(Request(TooLarge("PDU exceeds 65535 bytes")))
			},
			| _ => err!(Request(Unknown(warn!("Signing event for vhost failed: {e}")))),
		}
	})
}

/// Sign a JSON object using the bootstrap keypair (backwards compat).
#[implement(super::Service)]
pub fn sign_json(&self, object: &mut CanonicalJsonObject) -> Result {
	use ruma::signatures::sign_json;

	let server_name = self.services.globals.server_name().as_str();

	sign_json(server_name, self.keypair(), object).map_err(Into::into)
}

/// Sign a JSON object for a specific vhost.
/// Falls back to bootstrap keypair if the server name matches bootstrap.
#[implement(super::Service)]
pub fn sign_json_for_vhost(
	&self,
	object: &mut CanonicalJsonObject,
	server_name: &ServerName,
) -> Result {
	use ruma::signatures::sign_json;

	// Bootstrap server uses the primary keypair
	if server_name == self.services.globals.server_name() {
		return sign_json(server_name.as_str(), self.keypair(), object).map_err(Into::into);
	}

	// Look up vhost keypair
	let map = self
		.vhost_keypairs
		.read()
		.expect("vhost_keypairs lock poisoned");

	let vhost_kp = map
		.get(server_name)
		.ok_or_else(|| err!(Request(Unknown("Unknown vhost: {server_name}"))))?;

	sign_json(server_name.as_str(), &*vhost_kp.keypair, object).map_err(Into::into)
}
