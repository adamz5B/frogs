//! The process exit code for "the configuration is wrong, starting again
//! won't help". A supervised `frogs run --service-managed` uses a dedicated
//! code (78, `EX_CONFIG`) so systemd can be told not to restart it; every
//! other invocation keeps the plain exit code 1.

use std::io;
use std::sync::atomic::{AtomicI32, Ordering};

/// `EX_CONFIG` from `sysexits.h`; what a service-managed run exits with on a configuration refusal unless told otherwise.
pub const CONFIG_REFUSED: i32 = 78;

static CONFIG_REFUSAL_EXIT: AtomicI32 = AtomicI32::new(1);

/// Called once from `main` for a service-managed run.
pub fn set_config_refusal_exit(code: i32) {
    CONFIG_REFUSAL_EXIT.store(code, Ordering::Relaxed);
}

pub fn config_refusal_exit() -> i32 {
    CONFIG_REFUSAL_EXIT.load(Ordering::Relaxed)
}

/// Exits the process the way a configuration refusal should: after the caller has already printed its message.
pub fn exit_config_refused() -> ! {
    std::process::exit(config_refusal_exit())
}

/// Whether a startup error is the operator's configuration being wrong (a refusal, bad input
/// file, bad TLS material) rather than something a retry can fix (port in use, database down).
pub fn is_config_refusal(err: &io::Error) -> bool {
    matches!(err.kind(), io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_invalid_data_and_invalid_input_are_configuration_refusals() {
        assert!(is_config_refusal(&io::Error::new(io::ErrorKind::InvalidData, "x")));
        assert!(is_config_refusal(&io::Error::new(io::ErrorKind::InvalidInput, "x")));
        for kind in [
            io::ErrorKind::AddrInUse,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::NotFound,
            io::ErrorKind::Other,
        ] {
            assert!(!is_config_refusal(&io::Error::new(kind, "x")), "{kind:?}");
        }
    }

    #[test]
    fn the_default_refusal_exit_is_a_plain_one() {
        assert_eq!(config_refusal_exit(), 1);
    }
}
