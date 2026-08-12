use chrono::{DateTime, Utc};
use serde_json::Value;

use super::schema::DetailedField;

/// Applies a response field's `format`/`precision`/`sourceFormat` and
/// string-cleanup options to its resolved value. `null` passes straight
/// through regardless of `format` — there's nothing to coerce.
///
/// Formatters normalize (ISO 8601 dates, plain decimal numbers), they don't
/// localize — locale/display formatting is explicitly the frontend's job
/// per the design doc, so no locale-aware behavior belongs here.
pub fn apply(value: Value, detail: &DetailedField) -> Value {
    if value.is_null() {
        return Value::Null;
    }

    let value = match detail.format.as_deref() {
        Some("integer") => format_integer(&value),
        Some("decimal") => format_decimal(&value, detail.precision.unwrap_or(2)),
        Some("boolean") => format_boolean(&value),
        Some("date-time") => format_datetime(&value, detail.source_format.as_deref(), false),
        Some("date") => format_datetime(&value, detail.source_format.as_deref(), true),
        _ => value,
    };

    apply_string_transforms(value, detail)
}

fn apply_string_transforms(value: Value, detail: &DetailedField) -> Value {
    let Value::String(mut s) = value else {
        return value;
    };
    if detail.trim {
        s = s.trim().to_string();
    }
    if detail.uppercase {
        s = s.to_uppercase();
    }
    if detail.lowercase {
        s = s.to_lowercase();
    }
    Value::String(s)
}

fn format_integer(value: &Value) -> Value {
    match value {
        Value::Number(n) => match n.as_i64() {
            Some(i) => Value::Number(i.into()),
            None => n.as_f64().map(|f| Value::Number((f.trunc() as i64).into())).unwrap_or(Value::Null),
        },
        Value::String(s) => s.trim().parse::<i64>().map(|i| Value::Number(i.into())).unwrap_or(Value::Null),
        Value::Bool(b) => Value::Number((*b as i64).into()),
        other => other.clone(),
    }
}

fn format_decimal(value: &Value, precision: usize) -> Value {
    let as_f64 = match value {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse::<f64>().ok(),
        _ => None,
    };
    match as_f64 {
        Some(f) => {
            let factor = 10f64.powi(precision as i32);
            let rounded = (f * factor).round() / factor;
            serde_json::Number::from_f64(rounded).map(Value::Number).unwrap_or(Value::Null)
        }
        None => Value::Null,
    }
}

fn format_boolean(value: &Value) -> Value {
    match value {
        Value::Bool(b) => Value::Bool(*b),
        Value::Number(n) => Value::Bool(n.as_i64().map(|i| i != 0).unwrap_or(true)),
        Value::String(s) => Value::Bool(matches!(s.trim().to_lowercase().as_str(), "true" | "1" | "yes")),
        other => other.clone(),
    }
}

/// `sourceFormat` picks how the *raw* value is interpreted before it's
/// normalized to ISO 8601: `unix-seconds`/`unix-millis` for epoch numbers,
/// `rfc3339` (the default, since that's what `SqlValue::Timestamp` already
/// produces) for a string already in some RFC 3339-compatible form.
fn format_datetime(value: &Value, source_format: Option<&str>, date_only: bool) -> Value {
    let as_epoch_millis = || value.as_i64().or_else(|| value.as_f64().map(|f| f as i64));

    let parsed: Option<DateTime<Utc>> = match source_format {
        Some("unix-seconds") => as_epoch_millis().and_then(|secs| DateTime::from_timestamp(secs, 0)),
        Some("unix-millis") => as_epoch_millis().and_then(DateTime::from_timestamp_millis),
        Some("rfc3339") | None => value
            .as_str()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc)),
        Some(_) => None,
    };

    match parsed {
        Some(dt) if date_only => Value::String(dt.format("%Y-%m-%d").to_string()),
        Some(dt) => Value::String(dt.to_rfc3339()),
        None => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detail(format: &str, precision: Option<usize>, source_format: Option<&str>) -> DetailedField {
        DetailedField {
            from: "sources.x.y".to_string(),
            format: Some(format.to_string()),
            precision,
            source_format: source_format.map(str::to_string),
            trim: false,
            uppercase: false,
            lowercase: false,
        }
    }

    #[test]
    fn null_passes_through_regardless_of_format() {
        let d = detail("integer", None, None);
        assert_eq!(apply(Value::Null, &d), Value::Null);
    }

    #[test]
    fn integer_truncates_a_float() {
        let d = detail("integer", None, None);
        assert_eq!(apply(serde_json::json!(2003.7), &d), serde_json::json!(2003));
    }

    #[test]
    fn decimal_rounds_to_the_given_precision() {
        let d = detail("decimal", Some(2), None);
        assert_eq!(apply(serde_json::json!(24500.126), &d), serde_json::json!(24500.13));
    }

    #[test]
    fn decimal_defaults_precision_to_two() {
        let d = detail("decimal", None, None);
        assert_eq!(apply(serde_json::json!(1.239), &d), serde_json::json!(1.24));
    }

    #[test]
    fn boolean_coerces_from_an_integer() {
        let d = detail("boolean", None, None);
        assert_eq!(apply(serde_json::json!(0), &d), serde_json::json!(false));
        assert_eq!(apply(serde_json::json!(1), &d), serde_json::json!(true));
    }

    #[test]
    fn date_time_converts_unix_seconds_to_rfc3339() {
        let d = detail("date-time", None, Some("unix-seconds"));
        // 2003-06-15T00:00:00Z
        assert_eq!(apply(serde_json::json!(1_055_635_200_i64), &d), serde_json::json!("2003-06-15T00:00:00+00:00"));
    }

    #[test]
    fn date_only_keeps_just_the_date_part() {
        let d = detail("date", None, Some("unix-seconds"));
        assert_eq!(apply(serde_json::json!(1_055_635_200_i64), &d), serde_json::json!("2003-06-15"));
    }

    #[test]
    fn date_time_defaults_to_parsing_an_rfc3339_string() {
        let d = detail("date-time", None, None);
        assert_eq!(
            apply(serde_json::json!("2026-07-16T10:03:00+00:00"), &d),
            serde_json::json!("2026-07-16T10:03:00+00:00")
        );
    }

    #[test]
    fn string_transforms_apply_together() {
        let mut d = detail("string", None, None);
        d.trim = true;
        d.uppercase = true;
        assert_eq!(apply(serde_json::json!("  honda  "), &d), serde_json::json!("HONDA"));
    }
}
