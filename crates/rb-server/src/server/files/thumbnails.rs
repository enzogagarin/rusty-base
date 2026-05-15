use super::super::{MAX_THUMB_EDGE, MAX_THUMB_SOURCE_BYTES, MAX_THUMB_SOURCE_PIXELS};
use super::StoredFile;
use std::io::Cursor;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ThumbMode {
    CropCenter,
    CropTop,
    CropBottom,
    Fit,
    ResizeWidth,
    ResizeHeight,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ThumbSpec {
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) mode: ThumbMode,
}

pub(crate) fn thumbnail_file(
    file: StoredFile,
    spec: &str,
    allowed_thumbs: &[String],
) -> StoredFile {
    let spec = spec.trim();
    if !allowed_thumbs.iter().any(|thumb| thumb == spec) {
        return file;
    }

    render_thumbnail(&file, spec).unwrap_or(file)
}

pub(crate) fn render_thumbnail(file: &StoredFile, spec: &str) -> Option<StoredFile> {
    if file.data.len() > MAX_THUMB_SOURCE_BYTES {
        return None;
    }

    let spec = parse_thumb_spec(spec)?;
    let format = image::guess_format(&file.data).ok()?;
    if !matches!(
        format,
        image::ImageFormat::Png
            | image::ImageFormat::Jpeg
            | image::ImageFormat::Gif
            | image::ImageFormat::WebP
    ) {
        return None;
    }

    let reader = image::ImageReader::with_format(Cursor::new(file.data.as_slice()), format);
    let (source_width, source_height) = reader.into_dimensions().ok()?;
    if source_width == 0 || source_height == 0 {
        return None;
    }
    if u64::from(source_width) * u64::from(source_height) > MAX_THUMB_SOURCE_PIXELS {
        return None;
    }

    let decoded = image::load_from_memory_with_format(&file.data, format).ok()?;
    let thumbnail = render_thumbnail_image(decoded, spec, source_width, source_height)?;
    let mut output = Cursor::new(Vec::new());
    thumbnail
        .write_to(&mut output, image::ImageFormat::Png)
        .ok()?;

    Some(StoredFile {
        content_type: "image/png".to_string(),
        data: output.into_inner(),
    })
}

pub(crate) fn parse_thumb_spec(value: &str) -> Option<ThumbSpec> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    let (size, suffix) = match value.chars().last()? {
        't' | 'b' | 'f' => (&value[..value.len() - 1], value.chars().last()),
        _ => (value, None),
    };
    let (width, height) = size.split_once('x')?;
    let width = width.parse::<u32>().ok()?;
    let height = height.parse::<u32>().ok()?;
    if (width == 0 && height == 0) || width > MAX_THUMB_EDGE || height > MAX_THUMB_EDGE {
        return None;
    }

    let mode = match (width, height, suffix) {
        (0, _, None | Some('f')) => ThumbMode::ResizeHeight,
        (_, 0, None | Some('f')) => ThumbMode::ResizeWidth,
        (0, _, Some('t') | Some('b')) | (_, 0, Some('t') | Some('b')) => return None,
        (_, _, Some('f')) => ThumbMode::Fit,
        (_, _, Some('t')) => ThumbMode::CropTop,
        (_, _, Some('b')) => ThumbMode::CropBottom,
        (_, _, None) => ThumbMode::CropCenter,
        _ => return None,
    };

    Some(ThumbSpec {
        width,
        height,
        mode,
    })
}

pub(crate) fn render_thumbnail_image(
    image: image::DynamicImage,
    spec: ThumbSpec,
    source_width: u32,
    source_height: u32,
) -> Option<image::DynamicImage> {
    match spec.mode {
        ThumbMode::ResizeWidth => {
            let height = scaled_dimension(source_height, spec.width, source_width)?;
            resize_image(image, spec.width, height)
        }
        ThumbMode::ResizeHeight => {
            let width = scaled_dimension(source_width, spec.height, source_height)?;
            resize_image(image, width, spec.height)
        }
        ThumbMode::Fit => {
            let scale = (spec.width as f64 / source_width as f64)
                .min(spec.height as f64 / source_height as f64);
            let width = bounded_dimension((source_width as f64 * scale).round())?;
            let height = bounded_dimension((source_height as f64 * scale).round())?;
            resize_image(image, width, height)
        }
        ThumbMode::CropCenter | ThumbMode::CropTop | ThumbMode::CropBottom => {
            let scale = (spec.width as f64 / source_width as f64)
                .max(spec.height as f64 / source_height as f64);
            let resize_width =
                bounded_dimension((source_width as f64 * scale).ceil())?.max(spec.width);
            let resize_height =
                bounded_dimension((source_height as f64 * scale).ceil())?.max(spec.height);
            let resized = resize_image(image, resize_width, resize_height)?;
            let x = resize_width.saturating_sub(spec.width) / 2;
            let y = match spec.mode {
                ThumbMode::CropTop => 0,
                ThumbMode::CropBottom => resize_height.saturating_sub(spec.height),
                _ => resize_height.saturating_sub(spec.height) / 2,
            };

            Some(resized.crop_imm(x, y, spec.width, spec.height))
        }
    }
}

pub(crate) fn resize_image(
    image: image::DynamicImage,
    width: u32,
    height: u32,
) -> Option<image::DynamicImage> {
    if width == 0 || height == 0 {
        return None;
    }
    if u64::from(width) * u64::from(height) > MAX_THUMB_SOURCE_PIXELS {
        return None;
    }

    Some(image.resize_exact(width, height, image::imageops::FilterType::Lanczos3))
}

pub(crate) fn scaled_dimension(
    source_side: u32,
    target_side: u32,
    source_target_side: u32,
) -> Option<u32> {
    bounded_dimension(source_side as f64 * target_side as f64 / source_target_side as f64)
}

pub(crate) fn bounded_dimension(value: f64) -> Option<u32> {
    if !value.is_finite() {
        return None;
    }

    let value = value.round().max(1.0);
    if value > f64::from(MAX_THUMB_EDGE) {
        return None;
    }

    Some(value as u32)
}
