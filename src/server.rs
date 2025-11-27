use crate::auth::{extract_tokens, get_auth_token, handle_unauthorized_error, unauthorized_error};
use crate::config::{Config, LandingPageConfig, TokenType};
use crate::file::Directory;
use crate::header::{self, ContentDisposition};
use crate::mime as mime_util;
use crate::paste::{Paste, PasteType};
use crate::util::{self, safe_path_join, token_to_dir_name};
use actix_files::NamedFile;
use actix_multipart::Multipart;
use actix_web::http::StatusCode;
use actix_web::middleware::ErrorHandlers;
use actix_web::{delete, error, get, post, web, Error, HttpRequest, HttpResponse};
use actix_web_grants::GrantsMiddleware;
use awc::Client;
use byte_unit::{Byte, UnitType};
use futures_util::stream::StreamExt;
use mime::TEXT_PLAIN_UTF_8;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::{Duration, UNIX_EPOCH};
use uts2ts;

/// Returns the upload path for a given token.
///
/// If tokens are configured and a valid token is provided, returns a token-specific
/// directory. Otherwise, returns the base upload path.
#[allow(deprecated)]
fn get_upload_path_for_token(request: &HttpRequest, config: &Config) -> PathBuf {
    // Only use per-token directories if tokens are configured (unified or legacy)
    if config.server.tokens.is_some()
        || config.server.auth_tokens.is_some()
        || config.server.delete_tokens.is_some()
    {
        if let Some(token) = get_auth_token(request, config) {
            let token_dir = token_to_dir_name(&token);
            return config.server.upload_path.join(token_dir);
        }
    }
    config.server.upload_path.clone()
}

/// Shows the landing page.
#[get("/")]
#[allow(deprecated)]
async fn index(config: web::Data<RwLock<Config>>) -> Result<HttpResponse, Error> {
    let mut config = config
        .read()
        .map_err(|_| error::ErrorInternalServerError("cannot acquire config"))?
        .clone();
    let redirect = HttpResponse::Found()
        .append_header(("Location", env!("CARGO_PKG_HOMEPAGE")))
        .finish();
    if config.server.landing_page.is_some() {
        if config.landing_page.is_none() {
            config.landing_page = Some(LandingPageConfig::default());
        }
        if let Some(ref mut landing_page) = config.landing_page {
            landing_page.text = config.server.landing_page;
        }
    }
    if config.server.landing_page_content_type.is_some() {
        if config.landing_page.is_none() {
            config.landing_page = Some(LandingPageConfig::default());
        }
        if let Some(ref mut landing_page) = config.landing_page {
            landing_page.content_type = config.server.landing_page_content_type;
        }
    }
    if let Some(mut landing_page) = config.landing_page {
        if let Some(file) = landing_page.file {
            landing_page.text = fs::read_to_string(file).ok();
        }
        match landing_page.text {
            Some(page) => Ok(HttpResponse::Ok()
                .content_type(
                    landing_page
                        .content_type
                        .unwrap_or(TEXT_PLAIN_UTF_8.to_string()),
                )
                .body(page)),
            None => Ok(redirect),
        }
    } else {
        Ok(redirect)
    }
}

/// File serving options (i.e. query parameters).
#[derive(Debug, Deserialize)]
struct ServeOptions {
    /// If set to `true`, change the MIME type to `application/octet-stream` and force downloading
    /// the file.
    download: bool,
}

/// Serves a file from the upload directory.
#[get("/{file}")]
async fn serve(
    request: HttpRequest,
    file: web::Path<String>,
    options: Option<web::Query<ServeOptions>>,
    config: web::Data<RwLock<Config>>,
) -> Result<HttpResponse, Error> {
    let config = config
        .read()
        .map_err(|_| error::ErrorInternalServerError("cannot acquire config"))?;
    
    // Determine the upload path to search in
    let upload_path = get_upload_path_for_token(&request, &config);
    
    // If auth tokens are configured, first check in the token-specific directory (if valid token provided)
    // Then fall back to searching all token directories
    let mut path = util::glob_match_file(safe_path_join(&upload_path, &*file)?)?;
    let mut paste_type = PasteType::File;
    
    if !path.exists() || path.is_dir() {
        // Try other paste types within the same upload path
        for type_ in &[PasteType::Url, PasteType::Oneshot, PasteType::OneshotUrl] {
            let alt_path = safe_path_join(type_.get_path(&upload_path)?, &*file)?;
            let alt_path = util::glob_match_file(alt_path)?;
            if alt_path.exists()
                || path.file_name().and_then(|v| v.to_str()) == Some(&type_.get_dir())
            {
                path = alt_path;
                paste_type = *type_;
                break;
            }
        }
    }
    
    // If still not found and tokens are configured, search all token directories
    #[allow(deprecated)]
    let tokens_configured = config.server.tokens.is_some()
        || config.server.auth_tokens.is_some()
        || config.server.delete_tokens.is_some();
    if (!path.is_file() || !path.exists()) && tokens_configured {
        if let Some(tokens) = config.get_tokens(TokenType::Auth) {
            for token in tokens {
                let token_upload_path = config.server.upload_path.join(token_to_dir_name(&token));
                if let Ok(token_path) = safe_path_join(&token_upload_path, &*file) {
                    let token_path = util::glob_match_file(token_path)?;
                    if token_path.is_file() && token_path.exists() {
                        path = token_path;
                        paste_type = PasteType::File;
                        break;
                    }
                }
                // Also check other paste types in this token directory
                for type_ in &[PasteType::Url, PasteType::Oneshot, PasteType::OneshotUrl] {
                    if let Ok(type_path) = type_.get_path(&token_upload_path) {
                        if let Ok(alt_path) = safe_path_join(&type_path, &*file) {
                            let alt_path = util::glob_match_file(alt_path)?;
                            if alt_path.is_file() && alt_path.exists() {
                                path = alt_path;
                                paste_type = *type_;
                                break;
                            }
                        }
                    }
                }
                if path.is_file() && path.exists() {
                    break;
                }
            }
        }
    }
    
    if !path.is_file() || !path.exists() {
        return Err(error::ErrorNotFound("file is not found or expired :(\n"));
    }
    match paste_type {
        PasteType::File | PasteType::RemoteFile | PasteType::Oneshot => {
            let mime_type = if options.map(|v| v.download).unwrap_or(false) {
                mime::APPLICATION_OCTET_STREAM
            } else {
                mime_util::get_mime_type(&config.paste.mime_override, file.to_string())
                    .map_err(error::ErrorInternalServerError)?
            };
            let response = NamedFile::open(&path)?
                .disable_content_disposition()
                .set_content_type(mime_type)
                .prefer_utf8(true)
                .into_response(&request);
            if paste_type.is_oneshot() {
                fs::rename(
                    &path,
                    path.with_file_name(format!(
                        "{}.{}",
                        file,
                        util::get_system_time()?.as_millis()
                    )),
                )?;
            }
            Ok(response)
        }
        PasteType::Url => Ok(HttpResponse::Found()
            .append_header(("Location", fs::read_to_string(&path)?))
            .finish()),
        PasteType::OneshotUrl => {
            let resp = HttpResponse::Found()
                .append_header(("Location", fs::read_to_string(&path)?))
                .finish();
            fs::rename(
                &path,
                path.with_file_name(format!("{}.{}", file, util::get_system_time()?.as_millis())),
            )?;
            Ok(resp)
        }
    }
}

/// Remove a file from the upload directory.
#[delete("/{file}")]
#[actix_web_grants::protect("TokenType::Delete", ty = TokenType, error = unauthorized_error)]
async fn delete(
    request: HttpRequest,
    file: web::Path<String>,
    config: web::Data<RwLock<Config>>,
) -> Result<HttpResponse, Error> {
    let config = config
        .read()
        .map_err(|_| error::ErrorInternalServerError("cannot acquire config"))?;
    
    // Use token-specific upload path
    let upload_path = get_upload_path_for_token(&request, &config);
    let path = util::glob_match_file(safe_path_join(&upload_path, &*file)?)?;
    if !path.is_file() || !path.exists() {
        return Err(error::ErrorNotFound("file is not found or expired :(\n"));
    }
    match fs::remove_file(path) {
        Ok(_) => info!("deleted file: {:?}", file.to_string()),
        Err(e) => {
            error!("cannot delete file: {}", e);
            return Err(error::ErrorInternalServerError("cannot delete file"));
        }
    }
    Ok(HttpResponse::Ok().body(String::from("file deleted\n")))
}

/// Expose version endpoint
#[get("/version")]
#[actix_web_grants::protect("TokenType::Auth", ty = TokenType, error = unauthorized_error)]
async fn version(config: web::Data<RwLock<Config>>) -> Result<HttpResponse, Error> {
    let config = config
        .read()
        .map_err(|_| error::ErrorInternalServerError("cannot acquire config"))?;
    if !config.server.expose_version.unwrap_or(false) {
        warn!("server is not configured to expose version endpoint");
        Err(error::ErrorNotFound(""))?;
    }

    let version = env!("CARGO_PKG_VERSION");
    Ok(HttpResponse::Ok().body(version.to_owned() + "\n"))
}

/// Handles file upload by processing `multipart/form-data`.
#[post("/")]
#[actix_web_grants::protect("TokenType::Auth", ty = TokenType, error = unauthorized_error)]
async fn upload(
    request: HttpRequest,
    mut payload: Multipart,
    client: web::Data<Client>,
    config: web::Data<RwLock<Config>>,
) -> Result<HttpResponse, Error> {
    let connection = request.connection_info().clone();
    let host = connection.realip_remote_addr().unwrap_or("unknown host");
    let server_url = match config
        .read()
        .map_err(|_| error::ErrorInternalServerError("cannot acquire config"))?
        .server
        .url
        .clone()
    {
        Some(v) => v,
        None => {
            format!("{}://{}", connection.scheme(), connection.host(),)
        }
    };
    let time = util::get_system_time()?;
    let mut expiry_date = header::parse_expiry_date(request.headers(), time)?;
    if expiry_date.is_none() {
        expiry_date = config
            .read()
            .map_err(|_| error::ErrorInternalServerError("cannot acquire config"))?
            .paste
            .default_expiry
            .and_then(|v| time.checked_add(v).map(|t| t.as_millis()));
    }
    
    // Get the token-specific upload path
    let token_upload_path = {
        let config = config
            .read()
            .map_err(|_| error::ErrorInternalServerError("cannot acquire config"))?;
        get_upload_path_for_token(&request, &config)
    };
    
    // Create the token-specific directory if it doesn't exist
    fs::create_dir_all(&token_upload_path)?;
    for paste_type in &[PasteType::Url, PasteType::Oneshot, PasteType::OneshotUrl] {
        fs::create_dir_all(paste_type.get_path(&token_upload_path)?)?;
    }
    
    let mut urls: Vec<String> = Vec::new();
    while let Some(item) = payload.next().await {
        let header_filename = header::parse_header_filename(request.headers())?;
        let mut field = item?;
        let content = ContentDisposition::from(
            field
                .content_disposition()
                .ok_or_else(|| {
                    error::ErrorInternalServerError("payload must contain content disposition")
                })?
                .clone(),
        );
        if let Ok(paste_type) = PasteType::try_from(&content) {
            let mut bytes = Vec::<u8>::new();
            while let Some(chunk) = field.next().await {
                bytes.append(&mut chunk?.to_vec());
            }
            if bytes.is_empty() {
                warn!("{} sent zero bytes", host);
                return Err(error::ErrorBadRequest("invalid file size"));
            }
            if paste_type != PasteType::Oneshot
                && paste_type != PasteType::RemoteFile
                && paste_type != PasteType::OneshotUrl
                && expiry_date.is_none()
                && !config
                    .read()
                    .map_err(|_| error::ErrorInternalServerError("cannot acquire config"))?
                    .paste
                    .duplicate_files
                    .unwrap_or(true)
            {
                let bytes_checksum = util::sha256_digest(&*bytes)?;
                // Check for duplicate files in the token-specific directory
                if let Some(file) = Directory::try_from(token_upload_path.as_path())?
                    .get_file(bytes_checksum)
                {
                    urls.push(format!(
                        "{}/{}\n",
                        server_url,
                        file.path
                            .file_name()
                            .map(|v| v.to_string_lossy())
                            .unwrap_or_default()
                    ));
                    continue;
                }
            }
            let mut paste = Paste {
                data: bytes.to_vec(),
                type_: paste_type,
            };
            let mut file_name = match paste.type_ {
                PasteType::File | PasteType::Oneshot => {
                    let config = config
                        .read()
                        .map_err(|_| error::ErrorInternalServerError("cannot acquire config"))?;
                    // Create a config clone with the token-specific upload path
                    let mut upload_config = config.clone();
                    upload_config.server.upload_path = token_upload_path.clone();
                    paste.store_file(
                        content.get_file_name()?,
                        expiry_date,
                        header_filename,
                        &upload_config,
                    )?
                }
                PasteType::RemoteFile => {
                    // Create a config with the token-specific upload path for remote file
                    let mut upload_config = config
                        .read()
                        .map_err(|_| error::ErrorInternalServerError("cannot acquire config"))?
                        .clone();
                    upload_config.server.upload_path = token_upload_path.clone();
                    paste
                        .store_remote_file(expiry_date, &client, &RwLock::new(upload_config))
                        .await?
                }
                PasteType::Url | PasteType::OneshotUrl => {
                    let config = config
                        .read()
                        .map_err(|_| error::ErrorInternalServerError("cannot acquire config"))?;
                    // Create a config clone with the token-specific upload path
                    let mut upload_config = config.clone();
                    upload_config.server.upload_path = token_upload_path.clone();
                    paste.store_url(expiry_date, header_filename, &upload_config)?
                }
            };
            info!(
                "{} ({}) is uploaded from {}",
                file_name,
                Byte::from_u128(paste.data.len() as u128)
                    .unwrap_or_default()
                    .get_appropriate_unit(UnitType::Decimal),
                host
            );
            let config = config
                .read()
                .map_err(|_| error::ErrorInternalServerError("cannot acquire config"))?;
            if let Some(handle_spaces_config) = config.server.handle_spaces {
                file_name = handle_spaces_config.process_filename(&file_name);
            }
            urls.push(format!("{server_url}/{file_name}\n"));
        } else {
            warn!("{} sent an invalid form field", host);
            return Err(error::ErrorBadRequest("invalid form field"));
        }
    }
    Ok(HttpResponse::Ok().body(urls.join("")))
}

/// File entry item for list endpoint.
#[derive(Serialize, Deserialize)]
pub struct ListItem {
    /// Uploaded file name.
    pub file_name: PathBuf,
    /// Size of the file in bytes.
    pub file_size: u64,
    /// ISO8601 formatted date-time of the moment the file was created (uploaded).
    pub creation_date_utc: Option<String>,
    /// ISO8601 formatted date-time string of the expiration timestamp if one exists for this file.
    pub expires_at_utc: Option<String>,
}

/// Returns the list of files.
#[get("/list")]
#[actix_web_grants::protect("TokenType::Auth", ty = TokenType, error = unauthorized_error)]
async fn list(
    request: HttpRequest,
    config: web::Data<RwLock<Config>>,
) -> Result<HttpResponse, Error> {
    let config = config
        .read()
        .map_err(|_| error::ErrorInternalServerError("cannot acquire config"))?
        .clone();
    if !config.server.expose_list.unwrap_or(false) {
        warn!("server is not configured to expose list endpoint");
        Err(error::ErrorNotFound(""))?;
    }
    
    // Use token-specific upload path
    let upload_path = get_upload_path_for_token(&request, &config);
    
    // If the upload path doesn't exist, return an empty list
    let entries: Vec<ListItem> = match fs::read_dir(&upload_path) {
        Ok(read_dir) => read_dir
            .filter_map(|entry| {
                entry.ok().and_then(|e| {
                    let metadata = match e.metadata() {
                        Ok(metadata) => {
                            if metadata.is_dir() {
                                return None;
                            }
                            metadata
                        }
                        Err(e) => {
                            error!("failed to read metadata: {e}");
                            return None;
                        }
                    };
                    let mut file_name = PathBuf::from(e.file_name());

                    let creation_date_utc = metadata.created().ok().map(|v| {
                        let millis = v
                            .duration_since(UNIX_EPOCH)
                            .expect("Time since UNIX epoch should be valid.")
                            .as_millis();
                        uts2ts::uts2ts(
                            i64::try_from(millis).expect("UNIX time should be smaller than i64::MAX")
                                / 1000,
                        )
                        .as_string()
                    });

                    let expires_at_utc = if let Some(expiration) = file_name
                        .extension()
                        .and_then(|ext| ext.to_str())
                        .and_then(|v| v.parse::<i64>().ok())
                    {
                        file_name.set_extension("");
                        if util::get_system_time().ok()?
                            > Duration::from_millis(expiration.try_into().ok()?)
                        {
                            return None;
                        }
                        Some(uts2ts::uts2ts(expiration / 1000).as_string())
                    } else {
                        None
                    };
                    Some(ListItem {
                        file_name,
                        file_size: metadata.len(),
                        creation_date_utc,
                        expires_at_utc,
                    })
                })
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    Ok(HttpResponse::Ok().json(entries))
}

/// Configures the server routes.
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("")
            .service(index)
            .service(version)
            .service(list)
            .service(serve)
            .service(upload)
            .service(delete)
            .route("", web::head().to(HttpResponse::MethodNotAllowed))
            .wrap(GrantsMiddleware::with_extractor(extract_tokens))
            .wrap(
                ErrorHandlers::new().handler(StatusCode::UNAUTHORIZED, handle_unauthorized_error),
            ),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CorsConfig, LandingPageConfig};
    use crate::middleware::ContentLengthLimiter;
    use crate::random::{RandomURLConfig, RandomURLType};
    use actix_web::body::MessageBody;
    use actix_web::body::{BodySize, BoxBody};
    use actix_web::error::Error;
    use actix_web::http::header::AUTHORIZATION;
    use actix_web::http::{header, StatusCode};
    use actix_web::test::{self, TestRequest};
    use actix_web::web::Data;
    use actix_web::App;
    use awc::ClientBuilder;
    use glob::glob;
    use std::fs::File;
    use std::io::Write;
    use std::path::PathBuf;
    use std::str;
    use std::thread;
    use std::time::Duration;

    fn get_multipart_request(data: &str, name: &str, filename: &str) -> TestRequest {
        let multipart_data = format!(
            "\r\n\
             --multipart_bound\r\n\
             Content-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\n\
             Content-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\r\n\
             {}\r\n\
             --multipart_bound--\r\n",
            name,
            filename,
            data.len(),
            data,
        );
        TestRequest::post()
            .insert_header((
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("multipart/mixed; boundary=\"multipart_bound\""),
            ))
            .insert_header((
                header::CONTENT_LENGTH,
                header::HeaderValue::from_str(&data.len().to_string())
                    .expect("cannot create header value"),
            ))
            .set_payload(multipart_data)
    }

    async fn assert_body(body: BoxBody, expected: &str) -> Result<(), Error> {
        if let BodySize::Sized(size) = body.size() {
            assert_eq!(size, expected.len() as u64);
            let body_bytes = actix_web::body::to_bytes(body).await?;
            let body_text = str::from_utf8(&body_bytes)?;
            assert_eq!(expected, body_text);
            Ok(())
        } else {
            Err(error::ErrorInternalServerError("unexpected body type"))
        }
    }

    #[actix_web::test]
    async fn test_index() {
        let config = Config::default();
        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .service(index),
        )
        .await;
        let request = TestRequest::default()
            .insert_header(("content-type", "text/plain"))
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(StatusCode::FOUND, response.status());
    }

    #[actix_web::test]
    async fn test_index_with_landing_page() -> Result<(), Error> {
        let config = Config {
            landing_page: Some(LandingPageConfig {
                text: Some(String::from("landing page")),
                ..Default::default()
            }),
            ..Default::default()
        };
        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .service(index),
        )
        .await;
        let request = TestRequest::default()
            .insert_header(("content-type", "text/plain"))
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(response.into_body(), "landing page").await?;
        Ok(())
    }

    #[actix_web::test]
    async fn test_index_with_landing_page_file() -> Result<(), Error> {
        let filename = "landing_page.txt";
        let config = Config {
            landing_page: Some(LandingPageConfig {
                file: Some(filename.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut file = File::create(filename)?;
        file.write_all("landing page from file".as_bytes())?;
        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .service(index),
        )
        .await;
        let request = TestRequest::default()
            .insert_header(("content-type", "text/plain"))
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(response.into_body(), "landing page from file").await?;
        fs::remove_file(filename)?;
        Ok(())
    }

    #[actix_web::test]
    async fn test_index_with_landing_page_file_not_found() -> Result<(), Error> {
        let filename = "landing_page.txt";
        let config = Config {
            landing_page: Some(LandingPageConfig {
                text: Some(String::from("landing page")),
                file: Some(filename.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .service(index),
        )
        .await;
        let request = TestRequest::default()
            .insert_header(("content-type", "text/plain"))
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(StatusCode::FOUND, response.status());
        Ok(())
    }

    #[actix_web::test]
    async fn test_version_without_auth() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.auth_tokens = Some(["test".to_string()].into());
        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let request = TestRequest::default()
            .insert_header(("content-type", "text/plain"))
            .uri("/version")
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(StatusCode::UNAUTHORIZED, response.status());
        assert_body(response.into_body(), "unauthorized\n").await?;
        Ok(())
    }

    #[actix_web::test]
    async fn test_version_without_config() -> Result<(), Error> {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(Config::default())))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let request = TestRequest::default()
            .insert_header(("content-type", "text/plain"))
            .uri("/version")
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());
        assert_body(response.into_body(), "").await?;
        Ok(())
    }

    #[actix_web::test]
    async fn test_version() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.expose_version = Some(true);
        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let request = TestRequest::default()
            .insert_header(("content-type", "text/plain"))
            .uri("/version")
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(
            response.into_body(),
            &(env!("CARGO_PKG_VERSION").to_owned() + "\n"),
        )
        .await?;
        Ok(())
    }

    #[actix_web::test]
    async fn test_list() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.expose_list = Some(true);

        let test_upload_dir = "test_upload";
        fs::create_dir(test_upload_dir)?;
        config.server.upload_path = PathBuf::from(test_upload_dir);

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let filename = "test_file.txt";
        let timestamp = util::get_system_time()?.as_secs().to_string();
        test::call_service(
            &app,
            get_multipart_request(&timestamp, "file", filename).to_request(),
        )
        .await;

        let request = TestRequest::default()
            .insert_header(("content-type", "text/plain"))
            .uri("/list")
            .to_request();
        let result: Vec<ListItem> = test::call_and_read_body_json(&app, request).await;

        assert_eq!(result.len(), 1);
        assert_eq!(
            result.first().expect("json object").file_name,
            PathBuf::from(filename)
        );

        fs::remove_dir_all(test_upload_dir)?;

        Ok(())
    }

    #[actix_web::test]
    async fn test_list_expired() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.expose_list = Some(true);

        let test_upload_dir = "test_upload";
        fs::create_dir(test_upload_dir)?;
        config.server.upload_path = PathBuf::from(test_upload_dir);

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let filename = "test_file.txt";
        let timestamp = util::get_system_time()?.as_secs().to_string();
        test::call_service(
            &app,
            get_multipart_request(&timestamp, "file", filename)
                .insert_header((
                    header::HeaderName::from_static("expire"),
                    header::HeaderValue::from_static("50ms"),
                ))
                .to_request(),
        )
        .await;

        thread::sleep(Duration::from_millis(500));

        let request = TestRequest::default()
            .insert_header(("content-type", "text/plain"))
            .uri("/list")
            .to_request();
        let result: Vec<ListItem> = test::call_and_read_body_json(&app, request).await;

        assert!(result.is_empty());

        fs::remove_dir_all(test_upload_dir)?;

        Ok(())
    }

    #[actix_web::test]
    async fn test_per_token_storage() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.expose_list = Some(true);

        let test_upload_dir = "test_upload_per_token";
        fs::create_dir_all(test_upload_dir)?;
        config.server.upload_path = PathBuf::from(test_upload_dir);
        
        // Set up auth tokens
        let token1 = "token1";
        let token2 = "token2";
        config.server.auth_tokens = Some([token1.to_string(), token2.to_string()].into());

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config.clone())))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        // Upload a file using token1
        let filename1 = "token1_file.txt";
        let content1 = "content from token1";
        let response1 = test::call_service(
            &app,
            get_multipart_request(content1, "file", filename1)
                .insert_header((AUTHORIZATION, header::HeaderValue::from_static("basic token1")))
                .to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response1.status());

        // Upload a file using token2
        let filename2 = "token2_file.txt";
        let content2 = "content from token2";
        let response2 = test::call_service(
            &app,
            get_multipart_request(content2, "file", filename2)
                .insert_header((AUTHORIZATION, header::HeaderValue::from_static("basic token2")))
                .to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response2.status());

        // Verify files are stored in token-specific directories
        let token1_dir = PathBuf::from(test_upload_dir).join(util::token_to_dir_name(token1));
        let token2_dir = PathBuf::from(test_upload_dir).join(util::token_to_dir_name(token2));
        
        assert!(token1_dir.join(filename1).exists(), "File should exist in token1's directory");
        assert!(token2_dir.join(filename2).exists(), "File should exist in token2's directory");
        assert!(!token1_dir.join(filename2).exists(), "Token2's file should NOT be in token1's directory");
        assert!(!token2_dir.join(filename1).exists(), "Token1's file should NOT be in token2's directory");

        // List files using token1 - should only see token1's file
        let list_request1 = TestRequest::get()
            .uri("/list")
            .insert_header((AUTHORIZATION, header::HeaderValue::from_static("basic token1")))
            .to_request();
        let result1: Vec<ListItem> = test::call_and_read_body_json(&app, list_request1).await;
        assert_eq!(result1.len(), 1);
        assert_eq!(result1[0].file_name, PathBuf::from(filename1));

        // List files using token2 - should only see token2's file
        let list_request2 = TestRequest::get()
            .uri("/list")
            .insert_header((AUTHORIZATION, header::HeaderValue::from_static("basic token2")))
            .to_request();
        let result2: Vec<ListItem> = test::call_and_read_body_json(&app, list_request2).await;
        assert_eq!(result2.len(), 1);
        assert_eq!(result2[0].file_name, PathBuf::from(filename2));

        // Verify that token1 can still access token2's file via serve endpoint
        let serve_request = TestRequest::get()
            .uri(&format!("/{filename2}"))
            .insert_header((AUTHORIZATION, header::HeaderValue::from_static("basic token1")))
            .to_request();
        let serve_response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::OK, serve_response.status());

        // Clean up
        fs::remove_dir_all(test_upload_dir)?;

        Ok(())
    }

    #[actix_web::test]
    async fn test_unified_tokens() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.expose_list = Some(true);

        let test_upload_dir = "test_upload_unified_tokens";
        fs::create_dir_all(test_upload_dir)?;
        config.server.upload_path = PathBuf::from(test_upload_dir);

        // Set up unified tokens (works for both auth and delete)
        let token1 = "unified_token1";
        let token2 = "unified_token2";
        config.server.tokens = Some([token1.to_string(), token2.to_string()].into());

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config.clone())))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        // Upload a file using token1
        let filename1 = "unified_token1_file.txt";
        let content1 = "content from unified_token1";
        let response1 = test::call_service(
            &app,
            get_multipart_request(content1, "file", filename1)
                .insert_header((
                    AUTHORIZATION,
                    header::HeaderValue::from_static("basic unified_token1"),
                ))
                .to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response1.status());

        // Upload a file using token2
        let filename2 = "unified_token2_file.txt";
        let content2 = "content from unified_token2";
        let response2 = test::call_service(
            &app,
            get_multipart_request(content2, "file", filename2)
                .insert_header((
                    AUTHORIZATION,
                    header::HeaderValue::from_static("basic unified_token2"),
                ))
                .to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response2.status());

        // Verify files are stored in token-specific directories
        let token1_dir = PathBuf::from(test_upload_dir).join(util::token_to_dir_name(token1));
        let token2_dir = PathBuf::from(test_upload_dir).join(util::token_to_dir_name(token2));

        assert!(
            token1_dir.join(filename1).exists(),
            "File should exist in token1's directory"
        );
        assert!(
            token2_dir.join(filename2).exists(),
            "File should exist in token2's directory"
        );

        // Token1 can delete their own file
        let delete_own_request = TestRequest::delete()
            .uri(&format!("/{filename1}"))
            .insert_header((
                AUTHORIZATION,
                header::HeaderValue::from_static("basic unified_token1"),
            ))
            .to_request();
        let delete_response = test::call_service(&app, delete_own_request).await;
        assert_eq!(StatusCode::OK, delete_response.status());
        assert!(!token1_dir.join(filename1).exists());

        // Token1 CANNOT delete token2's file (should fail with 404 - file not found in their folder)
        let delete_others_request = TestRequest::delete()
            .uri(&format!("/{filename2}"))
            .insert_header((
                AUTHORIZATION,
                header::HeaderValue::from_static("basic unified_token1"),
            ))
            .to_request();
        let delete_response = test::call_service(&app, delete_others_request).await;
        assert_eq!(StatusCode::NOT_FOUND, delete_response.status());
        assert!(
            token2_dir.join(filename2).exists(),
            "Token2's file should still exist"
        );

        // Clean up
        fs::remove_dir_all(test_upload_dir)?;

        Ok(())
    }

    #[actix_web::test]
    async fn test_auth() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.auth_tokens = Some(["test".to_string()].into());

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let response =
            test::call_service(&app, get_multipart_request("", "", "").to_request()).await;
        assert_eq!(StatusCode::UNAUTHORIZED, response.status());
        assert_body(response.into_body(), "unauthorized\n").await?;

        Ok(())
    }

    #[actix_web::test]
    async fn test_payload_limit() -> Result<(), Error> {
        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(Config::default())))
                .app_data(Data::new(Client::default()))
                .wrap(ContentLengthLimiter::new(Byte::from_u64(1)))
                .configure(configure_routes),
        )
        .await;

        let response = test::call_service(
            &app,
            get_multipart_request("test", "file", "test").to_request(),
        )
        .await;
        assert_eq!(StatusCode::PAYLOAD_TOO_LARGE, response.status());
        assert_body(response.into_body().boxed(), "upload limit exceeded").await?;

        Ok(())
    }

    #[actix_web::test]
    async fn test_delete_file() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.delete_tokens = Some(["test".to_string()].into());
        config.server.upload_path = env::current_dir()?;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let file_name = "test_file.txt";
        let timestamp = util::get_system_time()?.as_secs().to_string();
        test::call_service(
            &app,
            get_multipart_request(&timestamp, "file", file_name).to_request(),
        )
        .await;

        let request = TestRequest::delete()
            .insert_header((AUTHORIZATION, header::HeaderValue::from_static("test")))
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = test::call_service(&app, request).await;

        assert_eq!(StatusCode::OK, response.status());
        assert_body(response.into_body(), "file deleted\n").await?;

        let path = PathBuf::from(file_name);
        assert!(!path.exists());

        Ok(())
    }

    #[actix_web::test]
    async fn test_delete_file_without_token_in_config() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.upload_path = env::current_dir()?;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let file_name = "test_file.txt";
        let request = TestRequest::delete()
            .insert_header((AUTHORIZATION, header::HeaderValue::from_static("test")))
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = test::call_service(&app, request).await;

        assert_eq!(StatusCode::NOT_FOUND, response.status());
        assert_body(response.into_body(), "").await?;

        Ok(())
    }

    #[actix_web::test]
    async fn test_upload_file() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.upload_path = env::current_dir()?;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let file_name = "test_file.txt";
        let timestamp = util::get_system_time()?.as_secs().to_string();
        let response = test::call_service(
            &app,
            get_multipart_request(&timestamp, "file", file_name).to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(
            response.into_body(),
            &format!("http://localhost:8080/{file_name}\n"),
        )
        .await?;

        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(response.into_body(), &timestamp).await?;

        fs::remove_file(file_name)?;
        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        Ok(())
    }

    #[actix_web::test]
    async fn test_upload_file_override_filename() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.upload_path = env::current_dir()?;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let file_name = "test_file.txt";
        let header_filename = "fn_from_header.txt";
        let timestamp = util::get_system_time()?.as_secs().to_string();
        let response = test::call_service(
            &app,
            get_multipart_request(&timestamp, "file", file_name)
                .insert_header((
                    header::HeaderName::from_static("filename"),
                    header::HeaderValue::from_static("fn_from_header.txt"),
                ))
                .to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(
            response.into_body(),
            &format!("http://localhost:8080/{header_filename}\n"),
        )
        .await?;

        let serve_request = TestRequest::get()
            .uri(&format!("/{header_filename}"))
            .to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(response.into_body(), &timestamp).await?;

        fs::remove_file(header_filename)?;
        let serve_request = TestRequest::get()
            .uri(&format!("/{header_filename}"))
            .to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        Ok(())
    }

    #[actix_web::test]
    async fn test_upload_same_filename() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.upload_path = env::current_dir()?;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let file_name = "test_file.txt";
        let header_filename = "fn_from_header.txt";
        let timestamp = util::get_system_time()?.as_secs().to_string();
        let response = test::call_service(
            &app,
            get_multipart_request(&timestamp, "file", file_name)
                .insert_header((
                    header::HeaderName::from_static("filename"),
                    header::HeaderValue::from_static("fn_from_header.txt"),
                ))
                .to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(
            response.into_body(),
            &format!("http://localhost:8080/{header_filename}\n"),
        )
        .await?;

        let timestamp = util::get_system_time()?.as_secs().to_string();
        let response = test::call_service(
            &app,
            get_multipart_request(&timestamp, "file", file_name)
                .insert_header((
                    header::HeaderName::from_static("filename"),
                    header::HeaderValue::from_static("fn_from_header.txt"),
                ))
                .to_request(),
        )
        .await;
        assert_eq!(StatusCode::CONFLICT, response.status());
        assert_body(response.into_body(), "file already exists\n").await?;

        fs::remove_file(header_filename)?;

        Ok(())
    }

    #[actix_web::test]
    #[allow(deprecated)]
    async fn test_upload_duplicate_file() -> Result<(), Error> {
        let test_upload_dir = "test_upload";
        fs::create_dir(test_upload_dir)?;

        let mut config = Config::default();
        config.server.upload_path = PathBuf::from(&test_upload_dir);
        config.paste.duplicate_files = Some(false);
        config.paste.random_url = Some(RandomURLConfig {
            enabled: Some(true),
            type_: RandomURLType::Alphanumeric,
            ..Default::default()
        });

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let response = test::call_service(
            &app,
            get_multipart_request("test", "file", "x").to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response.status());
        let body = response.into_body();
        let first_body_bytes = actix_web::body::to_bytes(body).await?;

        let response = test::call_service(
            &app,
            get_multipart_request("test", "file", "x").to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response.status());
        let body = response.into_body();
        let second_body_bytes = actix_web::body::to_bytes(body).await?;

        assert_eq!(first_body_bytes, second_body_bytes);

        fs::remove_dir_all(test_upload_dir)?;

        Ok(())
    }

    #[actix_web::test]
    async fn test_upload_expiring_file() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.upload_path = env::current_dir()?;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let file_name = "test_file.txt";
        let timestamp = util::get_system_time()?.as_secs().to_string();
        let response = test::call_service(
            &app,
            get_multipart_request(&timestamp, "file", file_name)
                .insert_header((
                    header::HeaderName::from_static("expire"),
                    header::HeaderValue::from_static("20ms"),
                ))
                .to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(
            response.into_body(),
            &format!("http://localhost:8080/{file_name}\n"),
        )
        .await?;

        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(response.into_body(), &timestamp).await?;

        thread::sleep(Duration::from_millis(40));

        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        if let Some(glob_path) = glob(&format!("{file_name}.[0-9]*"))
            .map_err(error::ErrorInternalServerError)?
            .next()
        {
            fs::remove_file(glob_path.map_err(error::ErrorInternalServerError)?)?;
        }

        Ok(())
    }

    #[actix_web::test]
    async fn test_upload_remote_file() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.upload_path = env::current_dir()?;
        config.server.max_content_length = Byte::from_u128(30000).unwrap_or_default();

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config)))
                .app_data(Data::new(
                    ClientBuilder::new()
                        .timeout(Duration::from_secs(30))
                        .finish(),
                ))
                .configure(configure_routes),
        )
        .await;

        let file_name =
            "rp_test_3b5eeeee7a7326cd6141f54820e6356a0e9d1dd4021407cb1d5e9de9f034ed2f.png";
        let response = test::call_service(
            &app,
            get_multipart_request(
                "https://raw.githubusercontent.com/orhun/rustypaste/refs/heads/master/img/rp_test_3b5eeeee7a7326cd6141f54820e6356a0e9d1dd4021407cb1d5e9de9f034ed2f.png",
                "remote",
                file_name,
            )
            .to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(
            response.into_body().boxed(),
            &format!("http://localhost:8080/{file_name}\n"),
        )
        .await?;

        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::OK, response.status());

        let body = response.into_body();
        let body_bytes = actix_web::body::to_bytes(body).await?;
        assert_eq!(
            "3b5eeeee7a7326cd6141f54820e6356a0e9d1dd4021407cb1d5e9de9f034ed2f",
            util::sha256_digest(&*body_bytes)?
        );

        fs::remove_file(file_name)?;

        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        Ok(())
    }

    #[actix_web::test]
    async fn test_upload_url() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.upload_path = env::current_dir()?;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config.clone())))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let url_upload_path = PasteType::Url
            .get_path(&config.server.upload_path)
            .expect("Bad upload path");
        fs::create_dir_all(&url_upload_path)?;

        let response = test::call_service(
            &app,
            get_multipart_request(env!("CARGO_PKG_HOMEPAGE"), "url", "").to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(response.into_body(), "http://localhost:8080/url\n").await?;

        let serve_request = TestRequest::get().uri("/url").to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::FOUND, response.status());

        fs::remove_file(url_upload_path.join("url"))?;
        fs::remove_dir(url_upload_path)?;

        let serve_request = TestRequest::get().uri("/url").to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        Ok(())
    }

    #[actix_web::test]
    async fn test_upload_oneshot() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.upload_path = env::current_dir()?;

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config.clone())))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let oneshot_upload_path = PasteType::Oneshot
            .get_path(&config.server.upload_path)
            .expect("Bad upload path");
        fs::create_dir_all(&oneshot_upload_path)?;

        let file_name = "oneshot.txt";
        let timestamp = util::get_system_time()?.as_secs().to_string();
        let response = test::call_service(
            &app,
            get_multipart_request(&timestamp, "oneshot", file_name).to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(
            response.into_body(),
            &format!("http://localhost:8080/{file_name}\n"),
        )
        .await?;

        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(response.into_body(), &timestamp).await?;

        let serve_request = TestRequest::get()
            .uri(&format!("/{file_name}"))
            .to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        if let Some(glob_path) = glob(
            &oneshot_upload_path
                .join(format!("{file_name}.[0-9]*"))
                .to_string_lossy(),
        )
        .map_err(error::ErrorInternalServerError)?
        .next()
        {
            fs::remove_file(glob_path.map_err(error::ErrorInternalServerError)?)?;
        }
        fs::remove_dir(oneshot_upload_path)?;

        Ok(())
    }

    #[actix_web::test]
    async fn test_upload_oneshot_url() -> Result<(), Error> {
        let mut config = Config::default();
        config.server.upload_path = env::current_dir()?;

        let oneshot_url_suffix = "oneshot_url";

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(config.clone())))
                .app_data(Data::new(Client::default()))
                .configure(configure_routes),
        )
        .await;

        let url_upload_path = PasteType::OneshotUrl
            .get_path(&config.server.upload_path)
            .expect("Bad upload path");
        fs::create_dir_all(&url_upload_path)?;

        let response = test::call_service(
            &app,
            get_multipart_request(
                env!("CARGO_PKG_HOMEPAGE"),
                oneshot_url_suffix,
                oneshot_url_suffix,
            )
            .to_request(),
        )
        .await;
        assert_eq!(StatusCode::OK, response.status());
        assert_body(
            response.into_body(),
            &format!("http://localhost:8080/{oneshot_url_suffix}\n"),
        )
        .await?;

        // Make the oneshot_url request, ensure it is found.
        let serve_request = TestRequest::with_uri(&format!("/{oneshot_url_suffix}")).to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::FOUND, response.status());

        // Make the same request again, and ensure that the oneshot_url is not found.
        let serve_request = TestRequest::with_uri(&format!("/{oneshot_url_suffix}")).to_request();
        let response = test::call_service(&app, serve_request).await;
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        // Cleanup
        fs::remove_dir_all(url_upload_path)?;

        Ok(())
    }

    #[actix_web::test]
    async fn test_cors_headers() -> Result<(), Error> {
        let cors_config = CorsConfig {
            allowed_origins: vec!["https://paste.example.com".to_string()],
            allowed_methods: vec!["GET".to_string(), "POST".to_string(), "DELETE".to_string(), "OPTIONS".to_string()],
            allowed_headers: vec!["Authorization".to_string(), "Content-Type".to_string()],
        };

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(Config::default())))
                .app_data(Data::new(Client::default()))
                .wrap(cors_config.build())
                .configure(configure_routes),
        )
        .await;

        // Send a preflight OPTIONS request with an Origin header
        let request = TestRequest::default()
            .method(actix_web::http::Method::OPTIONS)
            .insert_header(("Origin", "https://paste.example.com"))
            .insert_header(("Access-Control-Request-Method", "POST"))
            .insert_header(("Access-Control-Request-Headers", "Authorization, Content-Type"))
            .uri("/")
            .to_request();
        let response = test::call_service(&app, request).await;
        
        // Check CORS headers are present
        assert!(response.headers().contains_key("access-control-allow-origin"));
        assert_eq!(
            response.headers().get("access-control-allow-origin").unwrap().to_str().unwrap(),
            "https://paste.example.com"
        );
        
        Ok(())
    }

    #[actix_web::test]
    async fn test_cors_wildcard_origin() -> Result<(), Error> {
        let cors_config = CorsConfig {
            allowed_origins: vec!["*".to_string()],
            allowed_methods: vec!["GET".to_string()],
            allowed_headers: vec![],
        };

        let app = test::init_service(
            App::new()
                .app_data(Data::new(RwLock::new(Config::default())))
                .app_data(Data::new(Client::default()))
                .wrap(cors_config.build())
                .configure(configure_routes),
        )
        .await;

        // Send a request with an Origin header
        let request = TestRequest::get()
            .insert_header(("Origin", "https://any-origin.com"))
            .uri("/")
            .to_request();
        let response = test::call_service(&app, request).await;
        
        // With wildcard, any origin should be allowed - actix-cors echoes the origin back
        assert!(response.headers().contains_key("access-control-allow-origin"));
        let allowed_origin = response.headers().get("access-control-allow-origin").unwrap().to_str().unwrap();
        // When allow_any_origin() is used, actix-cors echoes back the request origin
        assert!(allowed_origin == "*" || allowed_origin == "https://any-origin.com");
        
        Ok(())
    }
}
