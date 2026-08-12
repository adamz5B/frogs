use serde::Deserialize;

/// One entry in `security/schemes.json` — maps an OpenAPI security scheme
/// name (as it appears in `openapi.yaml`'s `security:`/`securitySchemes`)
/// to the verifier file that actually checks it.
#[derive(Debug, Clone, Deserialize)]
pub struct SchemeConfig {
    pub verifier: String,
}
