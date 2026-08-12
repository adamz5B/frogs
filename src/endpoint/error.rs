use crate::http::HttpError;
use crate::sql::SqlError;

/// Every way resolving one source can fail, kept structured (rather than a
/// flattened `String`) so it can be classified into one of the design
/// doc's canonical `config/errors/*.json` codes without pattern-matching
/// message text. `Config`/`NotFound` aren't driver-level failures — they're
/// resolve.rs's own interpretation of "no connection by that name", "the
/// script/request file doesn't exist", or "cardinality one, zero rows".
#[derive(Debug)]
pub enum SourceErrorCause {
    Sql(SqlError),
    Http(HttpError),
    NotFound,
    Config(String),
    /// A `"fail": "<code>"` mock (the testing framework's Point 2) injected
    /// this code directly, bypassing real SQL/HTTP execution entirely —
    /// `code` is already the final registry code, not something to further
    /// classify. This is what lets a test case exercise `onError`/
    /// `exposeDetail`/`optional` degradation/`debugMode` against the real
    /// error-handling logic instead of a re-implementation of it in the
    /// test runner.
    Mocked(String),
}

impl SourceErrorCause {
    /// The stable string code this failure classifies to — looked up in
    /// the `ErrorRegistry` for `httpStatus`/`exposeDetail`. `Config`
    /// failures (missing files, unimplemented features) aren't one of a
    /// datasource's own known failure modes, so they fall back to
    /// `unexpected.error` rather than inventing a code for them.
    pub fn code(&self) -> &str {
        match self {
            SourceErrorCause::Sql(SqlError::ConnectionFailed(_)) => "datasource.sql.connection_failed",
            SourceErrorCause::Sql(SqlError::QueryFailed(_)) => "datasource.sql.query_failed",
            SourceErrorCause::NotFound => "datasource.sql.not_found",
            SourceErrorCause::Http(HttpError::Request(_)) => "datasource.http.timeout",
            SourceErrorCause::Http(HttpError::UpstreamStatus(404)) => "datasource.http.not_found",
            SourceErrorCause::Http(_) => "datasource.http.upstream_error",
            SourceErrorCause::Config(_) => "unexpected.error",
            SourceErrorCause::Mocked(code) => code,
        }
    }

    /// The underlying human-readable message — only ever shown to a
    /// caller when the classified code's `exposeDetail` is true, or in
    /// `debugMode`.
    pub fn message(&self) -> String {
        match self {
            SourceErrorCause::Sql(e) => e.to_string(),
            SourceErrorCause::Http(e) => e.to_string(),
            SourceErrorCause::NotFound => "query returned no rows".to_string(),
            SourceErrorCause::Config(m) => m.clone(),
            SourceErrorCause::Mocked(code) => format!("mocked failure: {code}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_sql_connection_vs_query_failures_differently() {
        assert_eq!(
            SourceErrorCause::Sql(SqlError::ConnectionFailed("x".into())).code(),
            "datasource.sql.connection_failed"
        );
        assert_eq!(SourceErrorCause::Sql(SqlError::QueryFailed("x".into())).code(), "datasource.sql.query_failed");
    }

    #[test]
    fn classifies_not_found() {
        assert_eq!(SourceErrorCause::NotFound.code(), "datasource.sql.not_found");
        assert_eq!(SourceErrorCause::NotFound.message(), "query returned no rows");
    }

    #[test]
    fn classifies_http_request_failure_as_timeout() {
        assert_eq!(SourceErrorCause::Http(HttpError::Request("x".into())).code(), "datasource.http.timeout");
    }

    #[test]
    fn classifies_http_404_specifically() {
        assert_eq!(SourceErrorCause::Http(HttpError::UpstreamStatus(404)).code(), "datasource.http.not_found");
    }

    #[test]
    fn classifies_other_http_upstream_statuses_generically() {
        assert_eq!(SourceErrorCause::Http(HttpError::UpstreamStatus(500)).code(), "datasource.http.upstream_error");
    }

    #[test]
    fn config_problems_fall_back_to_unexpected_error() {
        assert_eq!(SourceErrorCause::Config("missing file".into()).code(), "unexpected.error");
    }

    #[test]
    fn a_mocked_failure_uses_its_injected_code_directly() {
        let cause = SourceErrorCause::Mocked("datasource.http.timeout".to_string());
        assert_eq!(cause.code(), "datasource.http.timeout");
        assert!(cause.message().contains("datasource.http.timeout"));
    }
}
