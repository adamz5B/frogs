use std::io;

/// Every SQL driver this specific binary was compiled with — a compile-time
/// fact (see `sql::connect_all`'s matching `#[cfg(feature = ...)]` arms),
/// not something any project's own config affects. SQLite is always present
/// (a base feature, not optional — see Cargo.toml's `[features]` block);
/// Postgres remains the one compile-time choice. Pure and gate-free so it
/// can be unit-tested directly against whatever features the test binary
/// itself happens to be built with, rather than only exercised indirectly
/// through `list`'s printed output.
#[allow(unused_mut)] // only mutated when the `postgres`/`mysql`/`mssql` features add another push below
fn compiled_drivers() -> Vec<&'static str> {
    let mut drivers = vec!["sqlite"];
    #[cfg(feature = "postgres")]
    drivers.push("postgres");
    #[cfg(feature = "mysql")]
    drivers.push("mysql");
    #[cfg(feature = "mssql")]
    drivers.push("mssql");
    drivers
}

/// `frogs drivers list` — reports which drivers a given binary was built
/// with (design doc: "useful for a Docker image README or a pre-deploy
/// sanity check"). Doesn't touch `cwd` at all, unlike every other command:
/// this is a property of the binary itself, not of any particular project,
/// so it works the same from anywhere, project or no project. Never an
/// empty list — SQLite is always compiled in, so there's no "no drivers at
/// all" case to report.
pub fn list() -> io::Result<()> {
    println!("SQL drivers compiled into this binary:");
    for driver in compiled_drivers() {
        println!("  - {driver}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_is_always_listed_regardless_of_which_other_features_are_compiled_in() {
        assert!(compiled_drivers().contains(&"sqlite"));
    }

    #[test]
    #[cfg(feature = "postgres")]
    fn postgres_is_listed_when_its_feature_is_compiled_in() {
        assert!(compiled_drivers().contains(&"postgres"));
    }

    #[test]
    #[cfg(not(feature = "postgres"))]
    fn postgres_is_absent_when_its_feature_is_not_compiled_in() {
        assert!(!compiled_drivers().contains(&"postgres"));
    }

    #[test]
    #[cfg(feature = "mssql")]
    fn mssql_is_listed_when_its_feature_is_compiled_in() {
        assert!(compiled_drivers().contains(&"mssql"));
    }

    #[test]
    #[cfg(not(feature = "mssql"))]
    fn mssql_is_absent_when_its_feature_is_not_compiled_in() {
        assert!(!compiled_drivers().contains(&"mssql"));
    }

    #[test]
    fn list_never_fails_regardless_of_which_drivers_are_compiled_in() {
        assert!(list().is_ok());
    }
}
