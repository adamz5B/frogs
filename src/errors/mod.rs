mod discovered;
mod registry;

pub use discovered::{DiscoveredEntry, DiscoveredErrors};
pub use registry::{ConflictingCode, ErrorDefinition, ErrorRegistry, LoadError, UNEXPECTED_ERROR_CODE};
