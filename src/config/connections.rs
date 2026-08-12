use std::collections::HashMap;

use serde::Deserialize;

/// One entry in `config/connections.json`. Only `driver` is fixed — it
/// selects which compiled-in `SqlDriver` implementation to use — the rest
/// of a connection's shape (host/port/database/user/passwordEnv today,
/// something else for a future driver) is driver-specific, so it's kept as
/// a flattened bag rather than a fixed struct.
#[derive(Debug, Clone, Deserialize)]
pub struct ConnectionConfig {
    pub driver: String,
    #[serde(flatten)]
    pub settings: HashMap<String, serde_json::Value>,
}
