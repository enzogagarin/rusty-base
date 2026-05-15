pub(crate) fn text_matches_pattern(value: &str, pattern: &str) -> bool {
    if pattern.is_empty() {
        return true;
    }

    if let Some(inner) = pattern
        .strip_prefix("^[")
        .and_then(|rest| rest.split_once(']'))
    {
        let (class, suffix) = inner;
        let mut chars = value.chars();
        let Some(first) = chars.next() else {
            return false;
        };
        if !ascii_class_matches(class, first) {
            return false;
        }

        return match suffix {
            ".+" | ".+$" => chars.next().is_some(),
            ".*" | ".*$" => true,
            "+" | "+$" => value.chars().all(|ch| ascii_class_matches(class, ch)),
            "*" | "*$" => value.chars().all(|ch| ascii_class_matches(class, ch)),
            "$" | "" => value.chars().count() == 1,
            _ => false,
        };
    }

    let anchored_start = pattern.strip_prefix('^');
    let anchored = anchored_start.unwrap_or(pattern);
    let anchored_end = anchored.strip_suffix('$');
    let literal = anchored_end.unwrap_or(anchored);
    if literal_contains_regex_meta(literal) {
        return false;
    }

    match (anchored_start.is_some(), anchored_end.is_some()) {
        (true, true) => value == literal,
        (true, false) => value.starts_with(literal),
        (false, true) => value.ends_with(literal),
        (false, false) => value.contains(literal),
    }
}

pub(crate) fn ascii_class_matches(class: &str, ch: char) -> bool {
    if !ch.is_ascii() {
        return false;
    }
    let chars = class.chars().collect::<Vec<_>>();
    let mut index = 0;
    while index < chars.len() {
        if index + 2 < chars.len() && chars[index + 1] == '-' {
            if chars[index] <= ch && ch <= chars[index + 2] {
                return true;
            }
            index += 3;
        } else {
            if chars[index] == ch {
                return true;
            }
            index += 1;
        }
    }

    false
}

pub(crate) fn literal_contains_regex_meta(value: &str) -> bool {
    value.chars().any(|ch| {
        matches!(
            ch,
            '[' | ']' | '(' | ')' | '{' | '}' | '+' | '*' | '?' | '|' | '\\' | '.'
        )
    })
}
