use std::io;

/// Every SQL driver this specific binary was compiled with — a compile-time
/// fact (see `sql::connect_all`'s matching `#[cfg(feature = ...)]` arms),
/// not something any project's own config affects. Pure and gate-free so it
/// can be unit-tested directly against whatever features the test binary
/// itself happens to be built with, rather than only exercised indirectly
/// through `list`'s printed output.
fn compiled_drivers() -> Vec<&'static str> {
    let mut drivers = Vec::new();
    #[cfg(feature = "postgres")]
    drivers.push("postgres");
    #[cfg(feature = "sqlite")]
    drivers.push("sqlite");
    drivers
}

/// `frogs drivers list` — reports which drivers a given binary was built
/// with (design doc: "useful for a Docker image README or a pre-deploy
/// sanity check"). Doesn't touch `cwd` at all, unlike every other command:
/// this is a property of the binary itself, not of any particular project,
/// so it works the same from anywhere, project or no project.
pub fn list() -> io::Result<()> {
    let drivers = compiled_drivers();
    if drivers.is_empty() {
        println!(
            "no SQL drivers compiled into this binary — rebuild with `--features postgres` and/or `--features \
             sqlite` to add one"
        );
    } else {
        println!("SQL drivers compiled into this binary:");
        for driver in drivers {
            println!("  - {driver}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    #[cfg(feature = "sqlite")]
    fn sqlite_is_listed_when_its_feature_is_compiled_in() {
        assert!(compiled_drivers().contains(&"sqlite"));
    }

    #[test]
    #[cfg(not(feature = "sqlite"))]
    fn sqlite_is_absent_when_its_feature_is_not_compiled_in() {
        assert!(!compiled_drivers().contains(&"sqlite"));
    }

    #[test]
    fn list_never_fails_regardless_of_which_drivers_are_compiled_in() {
        assert!(list().is_ok());
    }
}
