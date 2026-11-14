//! A command's outcome as data: lines and errors a caller renders itself, instead of a command that
//! prints and exits. The CLI renders them with `ReportLine::render` (byte-identical to the old
//! `println!`s); the authoring MCP server serialises them.

use std::io;

use crate::config::ConfigLoadError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Severity {
    Error,
    Warning,
    Note,
    Info,
}

impl Severity {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Note => "note",
            Severity::Info => "info",
        }
    }
}

/// The exact text form a line takes on the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LineStyle {
    Plain,
    Indent,
    Error,
    Warning,
    Note,
    Bullet,
    /// `warning: <message>` on stderr.
    TopWarning,
    /// `error: <message>` on stderr.
    TopError,
}

#[derive(Debug, Clone)]
pub(crate) struct ReportLine {
    pub severity: Severity,
    /// Whether the line counts toward the problem total.
    pub problem: bool,
    pub section: &'static str,
    pub message: String,
    pub file: Option<String>,
    pub style: LineStyle,
}

impl ReportLine {
    pub(crate) fn render(&self) -> String {
        match self.style {
            LineStyle::Plain => self.message.clone(),
            LineStyle::Indent => format!("  {}", self.message),
            LineStyle::Error => format!("  error: {}", self.message),
            LineStyle::Warning => format!("  warning: {}", self.message),
            LineStyle::Note => format!("  note: {}", self.message),
            LineStyle::Bullet => format!("    - {}", self.message),
            LineStyle::TopWarning => format!("warning: {}", self.message),
            LineStyle::TopError => format!("error: {}", self.message),
        }
    }

    /// Whether the command line sends this line to stderr rather than stdout.
    pub(crate) fn is_stderr(&self) -> bool {
        matches!(self.style, LineStyle::TopWarning | LineStyle::TopError)
    }
}

/// An ordered list of lines with one constructor per text form. A `live` list also prints each line the moment
/// it is added (so the command line keeps its real-time ordering against log output); a plain one only collects.
#[derive(Debug, Default)]
pub(crate) struct Lines(pub Vec<ReportLine>, pub bool);

impl Lines {
    pub(crate) fn live() -> Self {
        Lines(Vec::new(), true)
    }

    fn push(&mut self, severity: Severity, problem: bool, section: &'static str, message: impl Into<String>, style: LineStyle) {
        let line = ReportLine {
            severity,
            problem,
            section,
            message: message.into(),
            file: None,
            style,
        };
        if self.1 {
            if line.is_stderr() {
                eprintln!("{}", line.render());
            } else {
                println!("{}", line.render());
            }
        }
        self.0.push(line);
    }

    pub(crate) fn plain(&mut self, section: &'static str, message: impl Into<String>) {
        self.push(Severity::Info, false, section, message, LineStyle::Plain);
    }

    pub(crate) fn top_warning(&mut self, section: &'static str, message: impl Into<String>) {
        self.push(Severity::Warning, false, section, message, LineStyle::TopWarning);
    }

    pub(crate) fn top_error(&mut self, section: &'static str, message: impl Into<String>) {
        self.push(Severity::Error, false, section, message, LineStyle::TopError);
    }

    pub(crate) fn info(&mut self, section: &'static str, message: impl Into<String>) {
        self.push(Severity::Info, false, section, message, LineStyle::Indent);
    }

    pub(crate) fn note(&mut self, section: &'static str, message: impl Into<String>) {
        self.push(Severity::Note, false, section, message, LineStyle::Note);
    }

    pub(crate) fn warning(&mut self, section: &'static str, message: impl Into<String>) {
        self.push(Severity::Warning, false, section, message, LineStyle::Warning);
    }

    /// `  error: <message>`, counted.
    pub(crate) fn error(&mut self, section: &'static str, message: impl Into<String>) {
        self.push(Severity::Error, true, section, message, LineStyle::Error);
    }

    /// An indented, counted problem line that carries its own label (`  openapi.yaml: FAILED — ...`).
    pub(crate) fn failure(&mut self, section: &'static str, message: impl Into<String>) {
        self.push(Severity::Error, true, section, message, LineStyle::Indent);
    }

    /// `    - <message>`, counted.
    pub(crate) fn bullet_problem(&mut self, section: &'static str, message: impl Into<String>) {
        self.push(Severity::Error, true, section, message, LineStyle::Bullet);
    }

    pub(crate) fn with_file(&mut self, file: impl Into<String>) {
        if let Some(last) = self.0.last_mut() {
            last.file = Some(file.into());
        }
    }

    #[cfg(test)]
    pub(crate) fn problems(&self) -> usize {
        self.0.iter().filter(|line| line.problem).count()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ErrorKind {
    Precondition,
    Config,
    Io,
    Refusal,
}

impl ErrorKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ErrorKind::Precondition => "precondition",
            ErrorKind::Config => "config",
            ErrorKind::Io => "io",
            ErrorKind::Refusal => "refusal",
        }
    }
}

/// What a command that would have printed an error and exited reports instead.
#[derive(Debug, Clone)]
pub(crate) struct CommandError {
    /// The text after `error: ` on the command line.
    pub message: String,
    pub exit_code: i32,
    pub kind: ErrorKind,
}

impl CommandError {
    pub(crate) fn precondition(message: impl Into<String>) -> Self {
        CommandError {
            message: message.into(),
            exit_code: 1,
            kind: ErrorKind::Precondition,
        }
    }
}

impl CommandError {
    /// The message `Config::load_or_exit` printed, as data.
    pub(crate) fn config_load(project_root: &std::path::Path, err: ConfigLoadError) -> Self {
        let mut error = CommandError::from(err);
        error.message = format!(
            "failed to load config for project at {}:
{}",
            project_root.display(),
            error.message
        );
        error
    }

    /// An error the command line prints as `error: <message>` before exiting with a plain 1.
    pub(crate) fn fatal(message: impl Into<String>) -> Self {
        Self::precondition(message)
    }

    /// Back to the `io::Error` a `?`-propagating caller expects; `main` derives the exit code from its kind.
    pub(crate) fn into_io(self) -> io::Error {
        let kind = if self.kind == ErrorKind::Refusal || self.kind == ErrorKind::Config {
            io::ErrorKind::InvalidData
        } else {
            io::ErrorKind::Other
        };
        io::Error::new(kind, self.message)
    }
}

impl From<ConfigLoadError> for CommandError {
    fn from(err: ConfigLoadError) -> Self {
        CommandError {
            message: err.to_string(),
            exit_code: crate::exit_codes::config_refusal_exit(),
            kind: ErrorKind::Config,
        }
    }
}

impl From<io::Error> for CommandError {
    fn from(err: io::Error) -> Self {
        if crate::exit_codes::is_config_refusal(&err) {
            CommandError {
                message: err.to_string(),
                exit_code: crate::exit_codes::config_refusal_exit(),
                kind: ErrorKind::Refusal,
            }
        } else {
            CommandError {
                message: err.to_string(),
                exit_code: 1,
                kind: ErrorKind::Io,
            }
        }
    }
}
