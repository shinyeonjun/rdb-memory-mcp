use std::fmt;

const REDACTION: &str = "***";

/// Redacts credentials from supported database connection string shapes.
pub fn redact_connection_string(value: &str) -> String {
    let value = redact_url_passwords(value);
    let value = redact_ado_passwords(&value);
    redact_oracle_passwords(&value)
}

/// Redacts a database error message, including any exact connection string echo.
pub fn redact_error_with_connection_string(
    error: impl fmt::Display,
    connection_string: &str,
) -> String {
    let message = error.to_string();
    let redacted_connection_string = redact_connection_string(connection_string);
    let message = message.replace(connection_string, &redacted_connection_string);
    redact_connection_string(&message)
}

fn redact_url_passwords(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut rest = value;

    while let Some(scheme_index) = rest.find("://") {
        let authority_start = scheme_index + 3;
        output.push_str(&rest[..authority_start]);

        let after_scheme = &rest[authority_start..];
        let authority_end = after_scheme
            .find(|ch| matches!(ch, '/' | '?' | '#'))
            .unwrap_or(after_scheme.len());
        let authority = &after_scheme[..authority_end];

        if let Some(at_index) = authority.rfind('@') {
            let userinfo = &authority[..at_index];
            if let Some(colon_index) = userinfo.rfind(':') {
                output.push_str(&userinfo[..=colon_index]);
                output.push_str(REDACTION);
                output.push_str(&authority[at_index..]);
            } else {
                output.push_str(authority);
            }
        } else {
            output.push_str(authority);
        }

        rest = &after_scheme[authority_end..];
    }

    output.push_str(rest);
    output
}

fn redact_ado_passwords(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for segment in value.split_inclusive(';') {
        let (body, suffix) = segment
            .strip_suffix(';')
            .map(|body| (body, ";"))
            .unwrap_or((segment, ""));

        if let Some(eq_index) = body.find('=') {
            let key = body[..eq_index]
                .trim()
                .replace(' ', "")
                .to_ascii_lowercase();
            if key == "password" || key == "pwd" {
                output.push_str(&body[..=eq_index]);
                output.push_str(REDACTION);
                output.push_str(suffix);
                continue;
            }
        }

        output.push_str(segment);
    }
    output
}

fn redact_oracle_passwords(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut cursor = 0;
    let mut search_from = 0;

    while let Some(relative_at) = value[search_from..].find('@') {
        let at_index = search_from + relative_at;
        let token_start = value[..at_index]
            .rfind(|ch: char| ch.is_whitespace() || ch == '\'' || ch == '"')
            .map(|index| index + 1)
            .unwrap_or(0);
        let token = &value[token_start..at_index];

        if let Some(slash_index) = token.find('/') {
            let user = &token[..slash_index];
            let password = &token[slash_index + 1..];
            if !user.is_empty() && !password.is_empty() && !user.contains(':') {
                output.push_str(&value[cursor..token_start + slash_index + 1]);
                output.push_str(REDACTION);
                cursor = at_index;
            }
        }

        search_from = at_index + 1;
    }

    output.push_str(&value[cursor..]);
    output
}

#[cfg(test)]
mod redact_tests {
    use super::*;

    #[test]
    fn redacts_url_connection_passwords() {
        assert_eq!(
            redact_connection_string("postgres://app:secret@db.example/app"),
            "postgres://app:***@db.example/app"
        );
        assert_eq!(
            redact_connection_string("mysql://user:password@localhost/db"),
            "mysql://user:***@localhost/db"
        );
    }

    #[test]
    fn redacts_ado_style_passwords() {
        assert_eq!(
            redact_connection_string(
                "server=tcp:localhost,1433;user=sa;password=Password123;database=app;TrustServerCertificate=true"
            ),
            "server=tcp:localhost,1433;user=sa;password=***;database=app;TrustServerCertificate=true"
        );
    }

    #[test]
    fn redacts_oracle_passwords() {
        assert_eq!(
            redact_connection_string("scott/tiger@localhost:1521/FREEPDB1"),
            "scott/***@localhost:1521/FREEPDB1"
        );
    }

    #[test]
    fn redacts_connection_string_echoes_in_errors() {
        let connection_string = "postgres://app:secret@db.example/app";
        assert_eq!(
            redact_error_with_connection_string(
                format!("failed to connect with {connection_string}"),
                connection_string
            ),
            "failed to connect with postgres://app:***@db.example/app"
        );
    }
}
