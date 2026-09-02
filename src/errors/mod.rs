mod discovered;
mod registry;

pub use discovered::DiscoveredErrors;
// `UNEXPECTED_ERROR_CODE` is only ever referenced from #[cfg(test)] code in
// other modules (config::tests, commands::generate::tests) — `registry` is
// a private submodule, so this re-export is their only path to it, even
// though the plain (non-test) build never uses it itself.
#[allow(unused_imports)]
pub use registry::{ErrorDefinition, ErrorRegistry, LoadError, UNEXPECTED_ERROR_CODE};
