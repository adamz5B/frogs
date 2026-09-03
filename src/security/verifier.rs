use serde::Deserialize;

/// A named parameter a verifier binds before running its `sql`/`http`
/// source — same `name`/`from` shape as an endpoint source's parameters,
/// except a verifier's own examples in the design doc only ever draw from
/// `header.*` (an API key or bearer token), so that's the only prefix
/// execution (Point 3) will need to support.
#[derive(Debug, Clone, Deserialize)]
pub struct Parameter {
    pub name: String,
    pub from: String,
}

/// One `security/verifiers/*.json` file. Deliberately the same `sql`/`http`
/// shape as an endpoint's own `SourceDef` (per the design doc: "a verifier
/// is just a datasource whose result is checked with `validIf` instead of
/// mapped into a response") — kept as its own type rather than reusing
/// `endpoint::schema::SourceDef` directly since that type is private to the
/// `endpoint` module and carries fields (`cardinality`, `onError`,
/// `optional`) that don't apply to a verifier at all.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum VerifierDef {
    Sql {
        connection: String,
        script: String,
        #[serde(default)]
        parameters: Vec<Parameter>,
        /// A single equality check, e.g. `"row.active = true"` — evaluated
        /// against the verifier's resolved result (Point 2). Not parsed
        /// here; kept as the raw string so a malformed expression is only
        /// ever an execution-time concern, not a config-load-time one.
        #[serde(rename = "validIf")]
        valid_if: String,
        /// `None` means "don't cache this verifier's result at all" — every
        /// request re-runs the check. Matters a lot for the DB/HTTP cases,
        /// per the design doc, but is meaningless without Point 4's cache.
        #[serde(rename = "cacheTtlSeconds", default)]
        cache_ttl_seconds: Option<u64>,
    },
    Http {
        request: String,
        #[serde(default)]
        parameters: Vec<Parameter>,
        #[serde(rename = "validIf")]
        valid_if: String,
        #[serde(rename = "cacheTtlSeconds", default)]
        cache_ttl_seconds: Option<u64>,
    },
}

impl VerifierDef {
    pub fn valid_if(&self) -> &str {
        match self {
            VerifierDef::Sql { valid_if, .. } | VerifierDef::Http { valid_if, .. } => valid_if,
        }
    }

    pub fn cache_ttl_seconds(&self) -> Option<u64> {
        match self {
            VerifierDef::Sql { cache_ttl_seconds, .. } | VerifierDef::Http { cache_ttl_seconds, .. } => *cache_ttl_seconds,
        }
    }

    pub fn parameters(&self) -> &[Parameter] {
        match self {
            VerifierDef::Sql { parameters, .. } | VerifierDef::Http { parameters, .. } => parameters,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_sql_verifier() {
        let json = r#"{
            "type": "sql",
            "connection": "vehicles_db",
            "script": "verify_api_key.sql",
            "parameters": [{ "name": "key", "from": "header.X-Api-Key" }],
            "validIf": "row.active = true",
            "cacheTtlSeconds": 30
        }"#;
        let verifier: VerifierDef = serde_json::from_str(json).unwrap();
        let VerifierDef::Sql {
            connection, script, parameters, ..
        } = &verifier
        else {
            panic!("expected a Sql verifier");
        };
        assert_eq!(connection, "vehicles_db");
        assert_eq!(script, "verify_api_key.sql");
        assert_eq!(parameters[0].from, "header.X-Api-Key");
        assert_eq!(verifier.valid_if(), "row.active = true");
        assert_eq!(verifier.cache_ttl_seconds(), Some(30));
    }

    #[test]
    fn parses_an_http_verifier() {
        let json = r#"{
            "type": "http",
            "request": "introspect_token.json",
            "parameters": [{ "name": "token", "from": "header.Authorization" }],
            "validIf": "response.active = true",
            "cacheTtlSeconds": 30
        }"#;
        let verifier: VerifierDef = serde_json::from_str(json).unwrap();
        assert!(matches!(verifier, VerifierDef::Http { .. }));
        assert_eq!(verifier.valid_if(), "response.active = true");
    }

    #[test]
    fn cache_ttl_seconds_is_optional() {
        let json = r#"{
            "type": "sql",
            "connection": "db",
            "script": "q.sql",
            "validIf": "row.active = true"
        }"#;
        let verifier: VerifierDef = serde_json::from_str(json).unwrap();
        assert_eq!(verifier.cache_ttl_seconds(), None);
        assert!(matches!(&verifier, VerifierDef::Sql { parameters, .. } if parameters.is_empty()));
    }
}
