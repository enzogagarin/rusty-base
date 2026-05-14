use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SafeCollectionIndexPlan {
    pub(crate) name: String,
    pub(crate) field_name: String,
    pub(crate) sql: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CollectionIndexSpec {
    pub(crate) index_name: String,
    pub(crate) collection_name: String,
    pub(crate) field_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CollectionIndexToken {
    Word(String),
    LParen,
    RParen,
    Comma,
}

pub(crate) fn safe_collection_index_plans(
    collection: &CollectionConfig,
) -> Result<Vec<SafeCollectionIndexPlan>, ServerError> {
    if !collection_owns_record_table(collection) {
        return Ok(Vec::new());
    }

    collection
        .indexes
        .iter()
        .filter_map(|index| safe_collection_index_plan(collection, index).transpose())
        .collect()
}

pub(crate) fn collection_index_warnings(
    collection: &CollectionConfig,
) -> Result<Vec<JsonValue>, ServerError> {
    let mut warnings = Vec::new();

    for index in &collection.indexes {
        let supported = collection_owns_record_table(collection)
            && safe_collection_index_plan(collection, index)?.is_some();
        if !supported {
            warnings.push(json!({
                "index": index,
                "code": "metadata_only_index",
                "message": "Index metadata was saved but not executed; Rusty Base currently executes only non-unique single-field scalar indexes."
            }));
        }
    }

    Ok(warnings)
}

pub(crate) fn apply_safe_collection_indexes(
    conn: &Connection,
    collection: &CollectionConfig,
) -> Result<(), ServerError> {
    for plan in safe_collection_index_plans(collection)? {
        conn.execute(&plan.sql, [])?;
    }
    Ok(())
}

pub(crate) fn drop_safe_collection_indexes(
    conn: &Connection,
    collection: &CollectionConfig,
) -> Result<(), ServerError> {
    for index in &collection.indexes {
        let name = safe_collection_index_name(&collection.name, index);
        conn.execute(
            &format!("DROP INDEX IF EXISTS {}", quote_identifier(&name)),
            [],
        )?;
    }
    Ok(())
}

pub(crate) fn safe_collection_index_plan(
    collection: &CollectionConfig,
    index: &str,
) -> Result<Option<SafeCollectionIndexPlan>, ServerError> {
    let Some(spec) = parse_collection_index(index)? else {
        return Ok(None);
    };
    if !spec.collection_name.eq_ignore_ascii_case(&collection.name)
        || !is_safe_identifier_part(&spec.index_name)
        || !is_safe_identifier_part(&spec.collection_name)
        || !is_safe_identifier_part(&spec.field_name)
    {
        return Ok(None);
    }
    let Some(field) = collection
        .fields
        .iter()
        .find(|field| field.name == spec.field_name)
    else {
        return Ok(None);
    };
    if !is_safe_index_field_kind(field.kind) {
        return Ok(None);
    }

    let name = safe_collection_index_name(&collection.name, index);
    let table_sql = quote_identifier(&record_table_name(&collection.name)?);
    let name_sql = quote_identifier(&name);
    let field_sql = json_data_extract(&field.name);
    Ok(Some(SafeCollectionIndexPlan {
        name,
        field_name: field.name.clone(),
        sql: format!("CREATE INDEX IF NOT EXISTS {name_sql} ON {table_sql} ({field_sql})"),
    }))
}

pub(crate) fn is_safe_index_field_kind(kind: CollectionFieldKind) -> bool {
    matches!(
        kind,
        CollectionFieldKind::Text
            | CollectionFieldKind::Email
            | CollectionFieldKind::Url
            | CollectionFieldKind::Editor
            | CollectionFieldKind::Number
            | CollectionFieldKind::Bool
            | CollectionFieldKind::DateTime
            | CollectionFieldKind::Select
            | CollectionFieldKind::AutoDate
    )
}

pub(crate) fn parse_collection_index(
    index: &str,
) -> Result<Option<CollectionIndexSpec>, ServerError> {
    let tokens = collection_index_tokens(index);
    let mut parser = CollectionIndexParser::new(&tokens);

    if !parser.consume_keyword("create") {
        return Ok(None);
    }
    if parser.consume_keyword("unique") {
        return Ok(None);
    }
    if !parser.consume_keyword("index") {
        return Ok(None);
    }
    if parser.consume_keyword("if")
        && (!parser.consume_keyword("not") || !parser.consume_keyword("exists"))
    {
        return Ok(None);
    }
    let Some(index_name) = parser.consume_word() else {
        return Ok(None);
    };
    if !parser.consume_keyword("on") {
        return Ok(None);
    }
    let Some(collection_name) = parser.consume_word() else {
        return Ok(None);
    };
    if !parser.consume_lparen() {
        return Ok(None);
    }
    let Some(field_name) = parser.consume_word() else {
        return Ok(None);
    };
    if parser.peek_keyword("asc") || parser.peek_keyword("desc") {
        parser.advance();
    }
    if parser.peek_comma() || !parser.consume_rparen() || !parser.is_done() {
        return Ok(None);
    }

    Ok(Some(CollectionIndexSpec {
        index_name,
        collection_name,
        field_name,
    }))
}

pub(crate) fn collection_index_tokens(input: &str) -> Vec<CollectionIndexToken> {
    let mut tokens = Vec::new();
    let mut chars = input.char_indices().peekable();
    while let Some((_, ch)) = chars.next() {
        match ch {
            ch if ch.is_whitespace() => {}
            '(' => tokens.push(CollectionIndexToken::LParen),
            ')' => tokens.push(CollectionIndexToken::RParen),
            ',' => tokens.push(CollectionIndexToken::Comma),
            '"' | '`' => {
                let Some(identifier) = read_sql_quoted_identifier(ch, &mut chars) else {
                    return Vec::new();
                };
                tokens.push(CollectionIndexToken::Word(identifier));
            }
            '[' => {
                let Some(identifier) = read_sql_bracket_identifier(&mut chars) else {
                    return Vec::new();
                };
                tokens.push(CollectionIndexToken::Word(identifier));
            }
            ch if is_safe_identifier_start(ch) => {
                let mut word = String::from(ch);
                while let Some((_, next)) = chars.peek() {
                    if next.is_ascii_alphanumeric() || *next == '_' {
                        word.push(*next);
                        chars.next();
                    } else {
                        break;
                    }
                }
                tokens.push(CollectionIndexToken::Word(word));
            }
            _ => return Vec::new(),
        }
    }
    tokens
}

pub(crate) fn read_sql_quoted_identifier<I>(
    quote: char,
    chars: &mut std::iter::Peekable<I>,
) -> Option<String>
where
    I: Iterator<Item = (usize, char)>,
{
    let mut value = String::new();
    while let Some((_, ch)) = chars.next() {
        if ch == quote {
            if chars.peek().is_some_and(|(_, next)| *next == quote) {
                value.push(quote);
                chars.next();
            } else {
                return Some(value);
            }
        } else {
            value.push(ch);
        }
    }
    None
}

pub(crate) fn read_sql_bracket_identifier<I>(chars: &mut std::iter::Peekable<I>) -> Option<String>
where
    I: Iterator<Item = (usize, char)>,
{
    let mut value = String::new();
    for (_, ch) in chars.by_ref() {
        if ch == ']' {
            return Some(value);
        }
        value.push(ch);
    }
    None
}

pub(crate) fn is_safe_identifier_start(ch: char) -> bool {
    ch.is_ascii_alphabetic() || ch == '_'
}

pub(crate) fn safe_collection_index_name(collection_name: &str, index: &str) -> String {
    format!(
        "_rb_idx_{}_{}",
        collection_name,
        stable_hash_hex(index.as_bytes())
    )
}

pub(crate) fn stable_hash_hex(bytes: &[u8]) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

pub(crate) struct CollectionIndexParser<'a> {
    tokens: &'a [CollectionIndexToken],
    position: usize,
}

impl<'a> CollectionIndexParser<'a> {
    pub(crate) fn new(tokens: &'a [CollectionIndexToken]) -> Self {
        Self {
            tokens,
            position: 0,
        }
    }

    pub(crate) fn is_done(&self) -> bool {
        self.position >= self.tokens.len()
    }

    pub(crate) fn advance(&mut self) {
        self.position += 1;
    }

    pub(crate) fn consume_keyword(&mut self, expected: &str) -> bool {
        if self.peek_keyword(expected) {
            self.advance();
            true
        } else {
            false
        }
    }

    pub(crate) fn peek_keyword(&self, expected: &str) -> bool {
        matches!(
            self.tokens.get(self.position),
            Some(CollectionIndexToken::Word(word)) if word.eq_ignore_ascii_case(expected)
        )
    }

    pub(crate) fn consume_word(&mut self) -> Option<String> {
        let word = match self.tokens.get(self.position) {
            Some(CollectionIndexToken::Word(word)) => word.clone(),
            _ => return None,
        };
        self.advance();
        Some(word)
    }

    pub(crate) fn consume_lparen(&mut self) -> bool {
        if matches!(
            self.tokens.get(self.position),
            Some(CollectionIndexToken::LParen)
        ) {
            self.advance();
            true
        } else {
            false
        }
    }

    pub(crate) fn consume_rparen(&mut self) -> bool {
        if matches!(
            self.tokens.get(self.position),
            Some(CollectionIndexToken::RParen)
        ) {
            self.advance();
            true
        } else {
            false
        }
    }

    pub(crate) fn peek_comma(&self) -> bool {
        matches!(
            self.tokens.get(self.position),
            Some(CollectionIndexToken::Comma)
        )
    }
}
