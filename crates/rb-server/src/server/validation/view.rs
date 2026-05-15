use super::super::ServerError;

const DENIED_VIEW_QUERY_TABLES: &[&str] = &[
    "_rb_auth_tokens",
    "_rb_auth_action_tokens",
    "_rb_auth_external_accounts",
    "_rb_file_tokens",
    "_rb_files",
    "_rb_settings",
    "_rb_collections",
    "_rb_realtime_subscriptions",
];

pub(crate) fn validate_view_query(query: &str) -> Result<(), ServerError> {
    let query = query.trim();
    let lowered = query.to_ascii_lowercase();
    if query.is_empty()
        || query.len() > 8192
        || !lowered.starts_with("select ")
        || query.contains(';')
        || query
            .chars()
            .any(|ch| ch.is_control() && !matches!(ch, '\n' | '\r' | '\t'))
    {
        return Err(ServerError::BadRequest(
            "viewQuery must be a single SELECT query".to_string(),
        ));
    }

    if let Some(table) = denied_view_query_table(query) {
        return Err(ServerError::BadRequest(format!(
            "viewQuery cannot reference internal table '{table}'"
        )));
    }

    Ok(())
}

pub(crate) fn denied_view_query_table(query: &str) -> Option<String> {
    view_query_identifiers(query).find_map(|identifier| {
        if is_denied_view_query_table(&identifier) {
            Some(identifier)
        } else {
            None
        }
    })
}

pub(crate) fn is_denied_view_query_table(identifier: &str) -> bool {
    let normalized = identifier.to_ascii_lowercase();
    normalized.starts_with("sqlite_")
        || normalized.starts_with("pragma_")
        || (normalized.starts_with("_rb_") && !normalized.starts_with("_rb_records_"))
        || DENIED_VIEW_QUERY_TABLES
            .iter()
            .any(|table| normalized == *table)
}

fn view_query_identifiers(query: &str) -> impl Iterator<Item = String> + '_ {
    let mut identifiers = Vec::new();
    let mut chars = query.char_indices().peekable();

    while let Some((_, ch)) = chars.next() {
        match ch {
            '\'' => skip_sql_single_quoted_string(&mut chars),
            '-' if chars.peek().is_some_and(|(_, next)| *next == '-') => {
                chars.next();
                skip_until_newline(&mut chars);
            }
            '/' if chars.peek().is_some_and(|(_, next)| *next == '*') => {
                chars.next();
                skip_sql_block_comment(&mut chars);
            }
            '"' | '`' => identifiers.push(read_quoted_identifier(ch, &mut chars)),
            '[' => identifiers.push(read_bracket_identifier(&mut chars)),
            ch if is_sql_identifier_start(ch) => {
                let mut identifier = String::from(ch);
                while let Some((_, next)) = chars.peek() {
                    if is_sql_identifier_part(*next) {
                        identifier.push(*next);
                        chars.next();
                    } else {
                        break;
                    }
                }
                identifiers.push(identifier);
            }
            _ => {}
        }
    }

    identifiers.into_iter()
}

fn skip_sql_single_quoted_string<I>(chars: &mut std::iter::Peekable<I>)
where
    I: Iterator<Item = (usize, char)>,
{
    while let Some((_, ch)) = chars.next() {
        if ch == '\'' {
            if chars.peek().is_some_and(|(_, next)| *next == '\'') {
                chars.next();
            } else {
                break;
            }
        }
    }
}

fn skip_until_newline<I>(chars: &mut std::iter::Peekable<I>)
where
    I: Iterator<Item = (usize, char)>,
{
    for (_, ch) in chars.by_ref() {
        if ch == '\n' {
            break;
        }
    }
}

fn skip_sql_block_comment<I>(chars: &mut std::iter::Peekable<I>)
where
    I: Iterator<Item = (usize, char)>,
{
    while let Some((_, ch)) = chars.next() {
        if ch == '*' && chars.peek().is_some_and(|(_, next)| *next == '/') {
            chars.next();
            break;
        }
    }
}

fn read_quoted_identifier<I>(quote: char, chars: &mut std::iter::Peekable<I>) -> String
where
    I: Iterator<Item = (usize, char)>,
{
    let mut identifier = String::new();
    while let Some((_, ch)) = chars.next() {
        if ch == quote {
            if chars.peek().is_some_and(|(_, next)| *next == quote) {
                identifier.push(quote);
                chars.next();
            } else {
                break;
            }
        } else {
            identifier.push(ch);
        }
    }
    identifier
}

fn read_bracket_identifier<I>(chars: &mut std::iter::Peekable<I>) -> String
where
    I: Iterator<Item = (usize, char)>,
{
    let mut identifier = String::new();
    for (_, ch) in chars.by_ref() {
        if ch == ']' {
            break;
        }
        identifier.push(ch);
    }
    identifier
}

fn is_sql_identifier_start(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphabetic()
}

fn is_sql_identifier_part(ch: char) -> bool {
    ch == '_' || ch == '$' || ch.is_ascii_alphanumeric()
}
