//! What `frogs generate` wrote under `api/config/` and `api/security/` for [`super::golden_spec::GOLDEN_SPEC`],
//! captured from the build before `$ref` resolution (relative path, content with CRLF
//! normalised to LF).

pub(super) const GOLDEN_CONFIG: &[(&str, &str)] = &[
    ("api/config/connections.json", r##"{}"##),
    (
        "api/config/errors/core.json",
        r##"{
  "datasource.sql.connection_failed": {
    "httpStatus": 500,
    "exposeDetail": false
  },
  "datasource.sql.query_failed": {
    "httpStatus": 500,
    "exposeDetail": false
  },
  "datasource.sql.constraint_violation": {
    "httpStatus": 409,
    "exposeDetail": true
  },
  "datasource.sql.not_found": {
    "httpStatus": 404,
    "exposeDetail": true
  },
  "datasource.http.timeout": {
    "httpStatus": 502,
    "exposeDetail": false
  },
  "datasource.http.not_found": {
    "httpStatus": 404,
    "exposeDetail": true
  },
  "datasource.http.upstream_error": {
    "httpStatus": 502,
    "exposeDetail": false
  },
  "auth.invalid_credentials": {
    "httpStatus": 401,
    "exposeDetail": true
  },
  "auth.verifier_unavailable": {
    "httpStatus": 500,
    "exposeDetail": false
  },
  "auth.client_cert_missing": {
    "httpStatus": 401,
    "exposeDetail": true
  },
  "auth.client_cert_expired": {
    "httpStatus": 401,
    "exposeDetail": true
  },
  "validation.missing_parameter": {
    "httpStatus": 400,
    "exposeDetail": true
  },
  "validation.invalid_type": {
    "httpStatus": 400,
    "exposeDetail": true
  },
  "unexpected.error": {
    "httpStatus": 500,
    "exposeDetail": false
  }
}"##,
    ),
    (
        "api/config/server.json",
        r##"{
  "debugMode": false,
  "features": {
    "metrics": true,
    "readyzCheck": true,
    "requestCorrelation": true,
    "rateLimiting": false,
    "serviceRegistry": false,
    "requestValidation": true,
    "cors": false
  },
  "autoMigrateEndpoints": true,
  "discoveredErrorsWarnThreshold": 20,
  "rateLimit": {
    "requestsPerSecond": 20,
    "burst": 40
  },
  "cors": {
    "allowedOrigins": []
  },
  "docsUi": {
    "mode": "off",
    "path": "docs"
  },
  "tls": {
    "mode": "off",
    "manual": null
  },
  "logging": {
    "directory": "runtime-logs",
    "level": "info"
  },
  "sourceCallTimeoutMs": 10000,
  "port": 8080,
  "apiRoot": "",
  "strictOpenApi": false,
  "caseSensitiveMethods": false,
  "endpointSymlinks": "contained"
}"##,
    ),
    ("api/security/schemes.json", r##"{}"##),
];
