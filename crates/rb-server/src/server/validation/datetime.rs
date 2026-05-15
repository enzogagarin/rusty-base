use super::super::{collections::CollectionField, JsonValue, ServerError};
use super::validation_error;

pub(crate) fn validate_datetime_field_value(
    field: &CollectionField,
    value: &JsonValue,
) -> Result<(), ServerError> {
    let Some(datetime) = value.as_str() else {
        return Err(invalid_datetime_field_value(field));
    };
    if !is_pocketbase_datetime(datetime) {
        return Err(invalid_datetime_field_value(field));
    }

    Ok(())
}

pub(crate) fn invalid_datetime_field_value(field: &CollectionField) -> ServerError {
    validation_error(
        "Failed to validate record.",
        &field.name,
        "validation_invalid_datetime",
        format!(
            "Field '{}' must be a datetime string in YYYY-MM-DD HH:MM:SS.mmmZ format.",
            field.name
        ),
    )
}

pub(crate) fn is_pocketbase_datetime(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 24 {
        return false;
    }
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b' '
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'.'
        || bytes[23] != b'Z'
    {
        return false;
    }

    let Some(year) = parse_fixed_digits(bytes, 0, 4) else {
        return false;
    };
    let Some(month) = parse_fixed_digits(bytes, 5, 2) else {
        return false;
    };
    let Some(day) = parse_fixed_digits(bytes, 8, 2) else {
        return false;
    };
    let Some(hour) = parse_fixed_digits(bytes, 11, 2) else {
        return false;
    };
    let Some(minute) = parse_fixed_digits(bytes, 14, 2) else {
        return false;
    };
    let Some(second) = parse_fixed_digits(bytes, 17, 2) else {
        return false;
    };
    if parse_fixed_digits(bytes, 20, 3).is_none() {
        return false;
    }

    year >= 1
        && (1..=12).contains(&month)
        && day >= 1
        && day <= days_in_month(year, month)
        && hour <= 23
        && minute <= 59
        && second <= 59
}

pub(crate) fn parse_fixed_digits(bytes: &[u8], start: usize, len: usize) -> Option<u32> {
    let mut value = 0u32;
    for byte in bytes.get(start..start + len)? {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value * 10 + u32::from(byte - b'0');
    }
    Some(value)
}

pub(crate) fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

pub(crate) fn is_leap_year(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}
