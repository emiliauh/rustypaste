use crate::paste::PasteType;
use actix_web::{error, Error as ActixError};
use glob::glob;
use lazy_regex::{lazy_regex, Lazy, Regex};
use path_clean::PathClean;
use ring::digest::{Context, SHA256};
use std::fmt::Write;
use std::io::{BufReader, Read};
use std::io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult};
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

/// Regex for matching the timestamp extension of a path.
pub static TIMESTAMP_EXTENSION_REGEX: Lazy<Regex> = lazy_regex!(r#"\.[0-9]{10,}$"#);

/// Returns the system time as [`Duration`](Duration).
pub fn get_system_time() -> Result<Duration, ActixError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(error::ErrorInternalServerError)
}

/// Returns the first _unexpired_ path matched by a custom glob pattern.
///
/// The file extension is accepted as a timestamp that points to the expiry date.
pub fn glob_match_file(mut path: PathBuf) -> Result<PathBuf, ActixError> {
    path = PathBuf::from(
        TIMESTAMP_EXTENSION_REGEX
            .replacen(
                path.to_str().ok_or_else(|| {
                    error::ErrorInternalServerError("path contains invalid characters")
                })?,
                1,
                "",
            )
            .to_string(),
    );
    if let Some(glob_path) = glob(&format!("{}.[0-9]*", path.to_string_lossy()))
        .map_err(error::ErrorInternalServerError)?
        .last()
    {
        let glob_path = glob_path.map_err(error::ErrorInternalServerError)?;
        if let Some(extension) = glob_path
            .extension()
            .and_then(|v| v.to_str())
            .and_then(|v| v.parse().ok())
        {
            if get_system_time()? < Duration::from_millis(extension) {
                path = glob_path;
            }
        }
    }
    Ok(path)
}

/// Returns the found expired files in the possible upload locations.
///
/// This function searches both in the base upload path and in all subdirectories
/// (including per-token directories). Fail-safe, omits errors.
pub fn get_expired_files(base_path: &Path) -> Vec<PathBuf> {
    let paste_types = [
        PasteType::File,
        PasteType::Oneshot,
        PasteType::Url,
        PasteType::OneshotUrl,
    ];
    
    let mut paths_to_search: Vec<PathBuf> = Vec::new();
    
    // Add paths from the base upload directory
    for paste_type in &paste_types {
        if let Ok(path) = paste_type.get_path(base_path) {
            paths_to_search.push(path);
        }
    }
    
    // Also search in all subdirectories (token directories)
    if let Ok(entries) = std::fs::read_dir(base_path) {
        for entry in entries.filter_map(Result::ok) {
            let entry_path = entry.path();
            if entry_path.is_dir() {
                // Add the token directory itself and its paste type subdirectories
                for paste_type in &paste_types {
                    if let Ok(path) = paste_type.get_path(&entry_path) {
                        paths_to_search.push(path);
                    }
                }
            }
        }
    }
    
    paths_to_search
        .into_iter()
        .filter_map(|v| glob(&v.join("*.[0-9]*").to_string_lossy()).ok())
        .flat_map(|glob| glob.filter_map(|v| v.ok()).collect::<Vec<PathBuf>>())
        .filter(|path| {
            if let Some(extension) = path
                .extension()
                .and_then(|v| v.to_str())
                .and_then(|v| v.parse().ok())
            {
                get_system_time()
                    .map(|system_time| system_time > Duration::from_millis(extension))
                    .unwrap_or(false)
            } else {
                false
            }
        })
        .collect()
}

/// Returns the SHA256 digest of the given input.
pub fn sha256_digest<R: Read>(input: R) -> Result<String, ActixError> {
    let mut reader = BufReader::new(input);
    let mut context = Context::new(&SHA256);
    let mut buffer = [0; 1024];
    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read != 0 {
            context.update(&buffer[..bytes_read]);
        } else {
            break;
        }
    }
    Ok(context
        .finish()
        .as_ref()
        .iter()
        .collect::<Vec<&u8>>()
        .iter()
        .try_fold::<String, _, IoResult<String>>(String::new(), |mut output, b| {
            write!(output, "{b:02x}").map_err(|e| IoError::other(e.to_string()))?;
            Ok(output)
        })?)
}

/// Joins the paths whilst ensuring the path doesn't drastically change.
/// `base` is assumed to be a trusted value.
pub fn safe_path_join<B: AsRef<Path>, P: AsRef<Path>>(base: B, part: P) -> IoResult<PathBuf> {
    let new_path = base.as_ref().join(part).clean();

    let cleaned_base = base.as_ref().clean();

    if !new_path.starts_with(cleaned_base) {
        return Err(IoError::new(
            IoErrorKind::InvalidData,
            format!(
                "{} is outside of {}",
                new_path.display(),
                base.as_ref().display()
            ),
        ));
    }

    Ok(new_path)
}

/// Returns a URL-safe Base64-encoded directory name from a token.
///
/// This is used to create per-token storage directories.
pub fn token_to_dir_name(token: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(token.as_bytes())
}

/// Returns the size of the directory at the given path.
///
/// This function is recursive, and will calculate the size of all files and directories.
/// If a symlink is encountered, the size of the symlink itself is counted, not its target.
///
/// Adopted from <https://docs.rs/fs_extra/latest/src/fs_extra/dir.rs.html>
pub fn get_dir_size(path: &Path) -> IoResult<u64> {
    let path_metadata = path.symlink_metadata()?;
    let mut size_in_bytes = 0;
    if path_metadata.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let entry_metadata = entry.metadata()?;
            if entry_metadata.is_dir() {
                size_in_bytes += get_dir_size(&entry.path())?;
            } else {
                size_in_bytes += entry_metadata.len();
            }
        }
    } else {
        size_in_bytes = path_metadata.len();
    }
    Ok(size_in_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use std::thread;
    #[test]
    fn test_system_time() -> Result<(), ActixError> {
        let system_time = get_system_time()?.as_millis();
        thread::sleep(Duration::from_millis(1));
        assert!(system_time < get_system_time()?.as_millis());
        Ok(())
    }

    #[test]
    fn test_glob_match() -> Result<(), ActixError> {
        let path = PathBuf::from(format!(
            "expired.file1.{}",
            get_system_time()?.as_millis() + 50
        ));
        fs::write(&path, String::new())?;
        assert_eq!(path, glob_match_file(PathBuf::from("expired.file1"))?);

        thread::sleep(Duration::from_millis(75));
        assert_eq!(
            PathBuf::from("expired.file1"),
            glob_match_file(PathBuf::from("expired.file1"))?
        );
        fs::remove_file(path)?;

        Ok(())
    }

    #[test]
    fn test_sha256sum() -> Result<(), ActixError> {
        assert_eq!(
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            sha256_digest(String::from("test").as_bytes())?
        );
        assert_eq!(
            "2fc36f72540bb9145e95e67c41dccdc440c95173257032e32e111ebd7b6df960",
            sha256_digest(env!("CARGO_PKG_NAME").as_bytes())?
        );
        Ok(())
    }

    #[test]
    fn test_get_expired_files() -> Result<(), ActixError> {
        let current_dir = env::current_dir()?;
        let expiration_time = get_system_time()?.as_millis() + 50;
        let path = PathBuf::from(format!("expired.file2.{expiration_time}"));
        fs::write(&path, String::new())?;
        assert_eq!(Vec::<PathBuf>::new(), get_expired_files(&current_dir));
        thread::sleep(Duration::from_millis(75));
        assert_eq!(
            vec![current_dir.join(&path)],
            get_expired_files(&current_dir)
        );
        fs::remove_file(path)?;
        assert_eq!(Vec::<PathBuf>::new(), get_expired_files(&current_dir));
        Ok(())
    }

    #[test]
    fn test_safe_join_path() {
        assert_eq!(safe_path_join("/foo", "bar").ok(), Some("/foo/bar".into()));
        assert_eq!(safe_path_join("/", "bar").ok(), Some("/bar".into()));
        assert_eq!(safe_path_join("/", "././bar").ok(), Some("/bar".into()));
        assert_eq!(
            safe_path_join("/foo/bar", "baz/").ok(),
            Some("/foo/bar/baz/".into())
        );
        assert_eq!(
            safe_path_join("/foo/bar/../", "baz").ok(),
            Some("/foo/baz".into())
        );

        assert!(safe_path_join("/foo", "/foobar").is_err());
        assert!(safe_path_join("/foo", "/bar").is_err());
        assert!(safe_path_join("/foo/bar", "..").is_err());
        assert!(safe_path_join("/foo/bar", "../").is_err());
    }

    #[test]
    fn test_token_to_dir_name() {
        // Test that token_to_dir_name produces consistent, filesystem-safe output
        assert_eq!("dGVzdC10b2tlbg", token_to_dir_name("test-token"));
        assert_eq!("c3VwZXItc2VjcmV0LXRva2VuMQ", token_to_dir_name("super-secret-token1"));
        // Verify no special characters that would be problematic for filesystems
        let result = token_to_dir_name("my-secret-token");
        assert!(!result.contains('/'));
        assert!(!result.contains('+'));
        assert!(!result.contains('='));
    }
}
