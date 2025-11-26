use crate::mime::MimeMatcher;
use crate::random::RandomURLConfig;
use crate::{
    AUTH_TOKENS_FILE_ENV, AUTH_TOKEN_ENV, DELETE_TOKENS_FILE_ENV, DELETE_TOKEN_ENV,
    TOKENS_FILE_ENV, TOKEN_ENV,
};
use byte_unit::Byte;
use config::{self, ConfigError};
use std::collections::HashSet;
use std::env;
use std::fs::read_to_string;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Configuration values.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Config {
    /// Configuration settings.
    #[serde(rename = "config")]
    pub settings: Option<Settings>,
    /// Server configuration.
    pub server: ServerConfig,
    /// Paste configuration.
    pub paste: PasteConfig,
    /// Landing page configuration.
    pub landing_page: Option<LandingPageConfig>,
}

/// General settings for configuration.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Settings {
    /// Refresh rate of the configuration file.
    #[serde(with = "humantime_serde")]
    pub refresh_rate: Duration,
}

/// Server configuration.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ServerConfig {
    /// The socket address to bind.
    pub address: String,
    /// URL that can be used to access the server externally.
    pub url: Option<String>,
    /// Number of workers to start.
    pub workers: Option<usize>,
    /// Maximum content length.
    pub max_content_length: Byte,
    /// Storage path.
    pub upload_path: PathBuf,
    /// Maximum upload directory size.
    pub max_upload_dir_size: Option<Byte>,
    /// Request timeout.
    #[serde(default, with = "humantime_serde")]
    pub timeout: Option<Duration>,
    /// Authentication token.
    #[deprecated(note = "use [server].tokens instead")]
    pub auth_token: Option<String>,
    /// Authentication tokens.
    #[deprecated(note = "use [server].tokens instead")]
    pub auth_tokens: Option<HashSet<String>>,
    /// Expose version.
    pub expose_version: Option<bool>,
    /// Landing page text.
    #[deprecated(note = "use the [landing_page] table")]
    pub landing_page: Option<String>,
    /// Landing page content-type.
    #[deprecated(note = "use the [landing_page] table")]
    pub landing_page_content_type: Option<String>,
    /// Handle spaces either via encoding or replacing.
    pub handle_spaces: Option<SpaceHandlingConfig>,
    /// Path of the JSON index.
    pub expose_list: Option<bool>,
    /// Authentication tokens for deleting.
    #[deprecated(note = "use [server].tokens instead")]
    pub delete_tokens: Option<HashSet<String>>,
    /// Unified tokens for both authentication and deletion.
    /// Each token grants both upload and delete permissions for the token's folder.
    pub tokens: Option<HashSet<String>>,
}

/// Enum representing different strategies for handling spaces in filenames.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SpaceHandlingConfig {
    /// Represents encoding spaces (e.g., using "%20").
    Encode,
    /// Represents replacing spaces with underscores.
    Replace,
}

impl SpaceHandlingConfig {
    /// Processes the given filename based on the specified space handling strategy.
    pub fn process_filename(&self, file_name: &str) -> String {
        match self {
            Self::Encode => file_name.replace(' ', "%20"),
            Self::Replace => file_name.replace(' ', "_"),
        }
    }
}

/// Landing page configuration.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct LandingPageConfig {
    /// Landing page text.
    pub text: Option<String>,
    /// Landing page file.
    pub file: Option<String>,
    /// Landing page content-type
    pub content_type: Option<String>,
}

/// Paste configuration.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PasteConfig {
    /// Random URL configuration.
    pub random_url: Option<RandomURLConfig>,
    /// Default file extension.
    pub default_extension: String,
    /// Media type override options.
    #[serde(default)]
    pub mime_override: Vec<MimeMatcher>,
    /// Media type blacklist.
    #[serde(default)]
    pub mime_blacklist: Vec<String>,
    /// Allow duplicate uploads.
    pub duplicate_files: Option<bool>,
    /// Default expiry time.
    #[serde(default, with = "humantime_serde")]
    pub default_expiry: Option<Duration>,
    /// Delete expired files.
    pub delete_expired_files: Option<CleanupConfig>,
}

/// Cleanup configuration.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CleanupConfig {
    /// Enable cleaning up.
    pub enabled: bool,
    /// Interval between clean-ups.
    #[serde(default, with = "humantime_serde")]
    pub interval: Duration,
}

/// Type of access token.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum TokenType {
    /// Token for authentication.
    Auth,
    /// Token for DELETE endpoint.
    Delete,
}

impl Config {
    /// Parses the config file and returns the values.
    pub fn parse(path: &Path) -> Result<Config, ConfigError> {
        config::Config::builder()
            .add_source(config::File::from(path))
            .add_source(config::Environment::default().separator("__"))
            .build()?
            .try_deserialize()
    }

    /// Retrieves all configured auth/delete tokens.
    ///
    /// This method supports both the unified `tokens` configuration and the deprecated
    /// separate `auth_tokens` and `delete_tokens` configurations. When using unified tokens,
    /// each token grants both upload and delete permissions for that token's folder.
    #[allow(deprecated)]
    pub fn get_tokens(&self, token_type: TokenType) -> Option<HashSet<String>> {
        let mut tokens: HashSet<String> = HashSet::new();

        // First, add unified tokens (these work for both Auth and Delete)
        if let Some(unified) = &self.server.tokens {
            tokens.extend(unified.clone());
        }

        // Add tokens from unified env var
        if let Ok(env_token) = env::var(TOKEN_ENV) {
            tokens.insert(env_token);
        }

        // Add tokens from unified tokens file
        if let Ok(env_path) = env::var(TOKENS_FILE_ENV) {
            match read_to_string(&env_path) {
                Ok(s) => {
                    s.lines().filter(|l| !l.trim().is_empty()).for_each(|l| {
                        tokens.insert(l.to_string());
                    });
                }
                Err(e) => {
                    error!("failed to read tokens from file ({env_path}) ({e})");
                }
            };
        }

        // Then, add type-specific tokens for backward compatibility
        match token_type {
            TokenType::Auth => {
                // Add deprecated auth_tokens
                if let Some(auth) = &self.server.auth_tokens {
                    tokens.extend(auth.clone());
                }

                // Add deprecated single auth_token
                if let Some(token) = &self.server.auth_token {
                    tokens.insert(token.to_string());
                }

                // Add from AUTH_TOKEN env var
                if let Ok(env_token) = env::var(AUTH_TOKEN_ENV) {
                    tokens.insert(env_token);
                }

                // Add from AUTH_TOKENS_FILE env var
                if let Ok(env_path) = env::var(AUTH_TOKENS_FILE_ENV) {
                    match read_to_string(&env_path) {
                        Ok(s) => {
                            s.lines().filter(|l| !l.trim().is_empty()).for_each(|l| {
                                tokens.insert(l.to_string());
                            });
                        }
                        Err(e) => {
                            error!(
                                "failed to read tokens from authentication file ({env_path}) ({e})"
                            );
                        }
                    };
                }
            }
            TokenType::Delete => {
                // Add deprecated delete_tokens
                if let Some(delete) = &self.server.delete_tokens {
                    tokens.extend(delete.clone());
                }

                // Add from DELETE_TOKEN env var
                if let Ok(env_token) = env::var(DELETE_TOKEN_ENV) {
                    tokens.insert(env_token);
                }

                // Add from DELETE_TOKENS_FILE env var
                if let Ok(env_path) = env::var(DELETE_TOKENS_FILE_ENV) {
                    match read_to_string(&env_path) {
                        Ok(s) => {
                            s.lines().filter(|l| !l.trim().is_empty()).for_each(|l| {
                                tokens.insert(l.to_string());
                            });
                        }
                        Err(e) => {
                            error!("failed to read deletion tokens from file ({env_path}) ({e})");
                        }
                    };
                }
            }
        }

        // filter out blank tokens
        tokens.retain(|v| !v.trim().is_empty());
        Some(tokens).filter(|v| !v.is_empty())
    }

    /// Print deprecation warnings.
    #[allow(deprecated)]
    pub fn warn_deprecation(&self) {
        if self.server.auth_token.is_some() {
            warn!("[server].auth_token is deprecated, please use [server].tokens");
        }
        if self.server.auth_tokens.is_some() {
            warn!("[server].auth_tokens is deprecated, please use [server].tokens");
        }
        if self.server.delete_tokens.is_some() {
            warn!("[server].delete_tokens is deprecated, please use [server].tokens");
        }
        if self.server.landing_page.is_some() {
            warn!("[server].landing_page is deprecated, please use [landing_page].text");
        }
        if self.server.landing_page_content_type.is_some() {
            warn!(
                "[server].landing_page_content_type is deprecated, please use [landing_page].content_type"
            );
        }
        if let Some(random_url) = &self.paste.random_url {
            if random_url.enabled.is_some() {
                warn!(
                    "[paste].random_url.enabled is deprecated, disable it by commenting out [paste].random_url"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_parse_config() -> Result<(), ConfigError> {
        let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config.toml");
        unsafe {
            env::set_var("SERVER__ADDRESS", "0.0.1.1");
        }
        let config = Config::parse(&config_path)?;
        assert_eq!("0.0.1.1", config.server.address);
        Ok(())
    }

    #[test]
    #[allow(deprecated)]
    fn test_parse_deprecated_config() -> Result<(), ConfigError> {
        let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config.toml");
        unsafe {
            env::set_var("SERVER__ADDRESS", "0.0.1.1");
        }
        let mut config = Config::parse(&config_path)?;
        config.paste.random_url = Some(RandomURLConfig {
            enabled: Some(true),
            ..RandomURLConfig::default()
        });
        assert_eq!("0.0.1.1", config.server.address);
        config.warn_deprecation();
        Ok(())
    }

    #[test]
    fn test_space_handling() {
        let processed_filename =
            SpaceHandlingConfig::Replace.process_filename("file with spaces.txt");
        assert_eq!("file_with_spaces.txt", processed_filename);
        let encoded_filename = SpaceHandlingConfig::Encode.process_filename("file with spaces.txt");
        assert_eq!("file%20with%20spaces.txt", encoded_filename);
    }

    #[test]
    fn test_get_tokens() -> Result<(), ConfigError> {
        let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config.toml");
        unsafe {
            env::set_var("AUTH_TOKEN", "env_auth");
            env::set_var("DELETE_TOKEN", "env_delete");
        }
        let mut config = Config::parse(&config_path)?;
        // empty tokens will be filtered
        config.server.auth_tokens =
            Some(["may_the_force_be_with_you".to_string(), "".to_string()].into());
        config.server.delete_tokens = Some(["i_am_your_father".to_string(), "".to_string()].into());
        assert_eq!(
            Some(HashSet::from([
                "env_auth".to_string(),
                "may_the_force_be_with_you".to_string()
            ])),
            config.get_tokens(TokenType::Auth)
        );
        assert_eq!(
            Some(HashSet::from([
                "env_delete".to_string(),
                "i_am_your_father".to_string()
            ])),
            config.get_tokens(TokenType::Delete)
        );
        unsafe {
            env::remove_var("AUTH_TOKEN");
            env::remove_var("DELETE_TOKEN");
        }

        // `get_tokens` returns `None` if no tokens are configured
        config.server.auth_tokens = Some(["  ".to_string()].into());
        config.server.delete_tokens = Some(HashSet::new());
        assert_eq!(None, config.get_tokens(TokenType::Auth));
        assert_eq!(None, config.get_tokens(TokenType::Delete));

        Ok(())
    }

    #[test]
    #[allow(deprecated)]
    fn test_unified_tokens() -> Result<(), ConfigError> {
        let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config.toml");
        let mut config = Config::parse(&config_path)?;

        // Set up unified tokens
        config.server.tokens = Some(["unified_token".to_string()].into());
        config.server.auth_tokens = None;
        config.server.delete_tokens = None;

        // Unified tokens should work for both Auth and Delete
        let auth_tokens = config.get_tokens(TokenType::Auth);
        let delete_tokens = config.get_tokens(TokenType::Delete);

        assert!(auth_tokens
            .as_ref()
            .is_some_and(|t| t.contains("unified_token")));
        assert!(delete_tokens
            .as_ref()
            .is_some_and(|t| t.contains("unified_token")));

        // Both should return the same tokens when only unified tokens are set
        assert_eq!(auth_tokens, delete_tokens);

        Ok(())
    }

    #[test]
    #[allow(deprecated)]
    fn test_mixed_tokens() -> Result<(), ConfigError> {
        let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config.toml");
        let mut config = Config::parse(&config_path)?;

        // Set up mixed tokens: unified, auth-only, and delete-only
        config.server.tokens = Some(["unified_token".to_string()].into());
        config.server.auth_tokens = Some(["auth_only_token".to_string()].into());
        config.server.delete_tokens = Some(["delete_only_token".to_string()].into());

        let auth_tokens = config.get_tokens(TokenType::Auth);
        let delete_tokens = config.get_tokens(TokenType::Delete);

        // Auth should include unified + auth_only
        assert!(auth_tokens
            .as_ref()
            .is_some_and(|t| t.contains("unified_token")));
        assert!(auth_tokens
            .as_ref()
            .is_some_and(|t| t.contains("auth_only_token")));
        assert!(!auth_tokens
            .as_ref()
            .is_some_and(|t| t.contains("delete_only_token")));

        // Delete should include unified + delete_only
        assert!(delete_tokens
            .as_ref()
            .is_some_and(|t| t.contains("unified_token")));
        assert!(delete_tokens
            .as_ref()
            .is_some_and(|t| t.contains("delete_only_token")));
        assert!(!delete_tokens
            .as_ref()
            .is_some_and(|t| t.contains("auth_only_token")));

        Ok(())
    }
}
