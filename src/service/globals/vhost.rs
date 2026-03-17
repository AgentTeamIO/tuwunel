use std::{
	collections::HashSet,
	sync::RwLock,
};

use ruma::{OwnedServerName, ServerName};

/// Registry of active virtual hosts.
/// The bootstrap vhost is the server_name from config.
/// Additional vhosts are added dynamically via admin API.
pub struct VhostRegistry {
	/// Bootstrap server_name (from config, always active)
	bootstrap: OwnedServerName,
	/// All active vhosts (including bootstrap)
	active: RwLock<HashSet<OwnedServerName>>,
}

impl VhostRegistry {
	pub fn new(bootstrap: OwnedServerName) -> Self {
		let mut active = HashSet::new();
		active.insert(bootstrap.clone());
		Self {
			bootstrap,
			active: RwLock::new(active),
		}
	}

	/// Check if a server name belongs to this instance (any vhost).
	#[inline]
	#[must_use]
	pub fn is_ours(&self, name: &ServerName) -> bool {
		let active = self.active.read().expect("vhost registry lock poisoned");
		active.contains(name)
	}

	/// Get the bootstrap server name (backwards compat).
	#[inline]
	#[must_use]
	pub fn bootstrap_name(&self) -> &OwnedServerName { &self.bootstrap }

	/// Add a new vhost (returns true if it was newly inserted).
	pub fn add(&self, name: OwnedServerName) -> bool {
		let mut active = self.active.write().expect("vhost registry lock poisoned");
		active.insert(name)
	}

	/// Remove a vhost (cannot remove bootstrap, returns false in that case).
	pub fn remove(&self, name: &ServerName) -> bool {
		if name == &*self.bootstrap {
			return false;
		}
		let mut active = self.active.write().expect("vhost registry lock poisoned");
		active.remove(name)
	}

	/// List all active vhosts.
	#[must_use]
	pub fn list(&self) -> Vec<OwnedServerName> {
		let active = self.active.read().expect("vhost registry lock poisoned");
		active.iter().cloned().collect()
	}
}

#[cfg(test)]
mod tests {
	use ruma::server_name;

	use super::*;

	#[test]
	fn bootstrap_is_ours() {
		let registry = VhostRegistry::new("example.com".try_into().unwrap());
		assert!(registry.is_ours(server_name!("example.com")));
	}

	#[test]
	fn unknown_is_not_ours() {
		let registry = VhostRegistry::new("example.com".try_into().unwrap());
		assert!(!registry.is_ours(server_name!("other.com")));
	}

	#[test]
	fn add_second_vhost() {
		let registry = VhostRegistry::new("example.com".try_into().unwrap());
		assert!(registry.add("tenant.example.com".try_into().unwrap()));
		assert!(registry.is_ours(server_name!("example.com")));
		assert!(registry.is_ours(server_name!("tenant.example.com")));
		assert!(!registry.is_ours(server_name!("unknown.com")));
	}

	#[test]
	fn cannot_remove_bootstrap() {
		let registry = VhostRegistry::new("example.com".try_into().unwrap());
		assert!(!registry.remove(server_name!("example.com")));
		assert!(registry.is_ours(server_name!("example.com")));
	}

	#[test]
	fn remove_added_vhost() {
		let registry = VhostRegistry::new("example.com".try_into().unwrap());
		registry.add("tenant.example.com".try_into().unwrap());
		assert!(registry.is_ours(server_name!("tenant.example.com")));
		assert!(registry.remove(server_name!("tenant.example.com")));
		assert!(!registry.is_ours(server_name!("tenant.example.com")));
	}

	#[test]
	fn list_vhosts() {
		let registry = VhostRegistry::new("example.com".try_into().unwrap());
		registry.add("a.example.com".try_into().unwrap());
		registry.add("b.example.com".try_into().unwrap());
		let mut list = registry.list();
		list.sort();
		assert_eq!(list.len(), 3);
	}

	#[test]
	fn bootstrap_name_returns_original() {
		let registry = VhostRegistry::new("example.com".try_into().unwrap());
		assert_eq!(registry.bootstrap_name().as_str(), "example.com");
	}
}
