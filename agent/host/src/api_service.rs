use reqwest::{Client, header::HeaderMap};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::Path, time::Duration};
use thiserror::Error;
use reqwest::StatusCode;

const DEFAULT_API_URL: &str = "http://2.228.138.42/run";

#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("UTF-8 conversion error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("Model error: {0}")]
    Model(String),
    #[error("Header error: {0}")]
    Header(String),
    #[error("Request failed: {status}, {message}")]
    RequestFailed {
        status: StatusCode,
        message: String,
    },
}

// Config Structures - come prima...
#[derive(Debug, Serialize, Deserialize)]
pub struct UomiConfig {
    pub local_file_path: String,
    #[serde(default)]
    pub api: ApiConfig,
    pub models: HashMap<String, ModelConfig>,
    #[serde(default)]
    pub ipfs: IpfsConfig,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ApiConfig {
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_retry_attempts")]
    pub retry_attempts: u32,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub chain_rpc_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ModelConfig {
    pub name: String,
    pub url: Option<String>,
    pub api_key: Option<String>,  
}


#[derive(Debug, Serialize, Deserialize, Default)]
pub struct IpfsConfig {
    #[serde(default = "default_ipfs_gateway")]
    pub gateway: String,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct Message {
    role: String,
    content: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct InputWrapper {
    messages: Vec<Message>,
}

fn default_timeout() -> u64 { 30000 }
fn default_retry_attempts() -> u32 { 3 }
fn default_ipfs_gateway() -> String { "https://ipfs.io/ipfs".to_string() }

pub fn get_config() -> Result<UomiConfig, ServiceError> {
    let input_str = include_str!("../../uomi.config.json");
    Ok(serde_json::from_str(input_str)?)
}

pub fn get_file() -> Result<Vec<u8>, ServiceError> {
    let config = get_config()?;
    let file_path = config.local_file_path;
    
    if !Path::new(&file_path).exists() {
        return Err(ServiceError::Config(format!("File not found: {}", file_path)));
    }
    
    Ok(std::fs::read(&file_path)?)
}

pub async fn get_file_from_cid(cid: &str) -> Result<Vec<u8>, ServiceError> {
    let config = get_config()?;
    let url = format!("{}/{}", config.ipfs.gateway, cid);
    
    let client = Client::builder()
        .timeout(Duration::from_millis(config.ipfs.timeout_ms))
        .build()?;
        
    let response = client
        .get(&url)
        .send()
        .await?;
        
    if !response.status().is_success() {
        return Err(ServiceError::RequestFailed {
            status: response.status(),
            message: response.text().await.unwrap_or_default(),
        });
    }
    
    Ok(response.bytes().await?.to_vec())
}

#[tokio::main]
pub async fn call_service_api(model_id: i32, data: Vec<u8>) -> Result<Vec<u8>, ServiceError> {
    let config = get_config()?;
    
    let model = config.models.get(&model_id.to_string())
        .ok_or_else(|| ServiceError::Model(format!("Invalid model ID: {}", model_id)))?;

    // Parse input data
    let input_str = String::from_utf8(data)?;
    let input: InputWrapper = serde_json::from_str(&input_str)?;

    let (url, request_body) = if let Some(model_url) = &model.url {
        // OpenAI-style request
        let request = serde_json::json!({
            "model": model.name,
            "messages": input.messages,
        });
        (model_url.clone(), request)
    } else {
        // Default request
        let request = serde_json::json!({
            "model": model.name,
            "input": input_str,
        });
        (DEFAULT_API_URL.to_string(), request)
    };

    let client = Client::builder()
        .timeout(Duration::from_millis(config.api.timeout_ms))
        .build()?;

    let mut headers = HeaderMap::new();
    
    // Aggiungi prima gli headers di base dalla configurazione
    for (key, value) in &config.api.headers {
        headers.insert(
            reqwest::header::HeaderName::from_bytes(key.as_bytes())
                .map_err(|e| ServiceError::Header(e.to_string()))?,
            reqwest::header::HeaderValue::from_str(value)
                .map_err(|e| ServiceError::Header(e.to_string()))?
        );
    }

    // Se il modello ha un URL personalizzato, controlla l'API key
    if model.url.is_some() {
        if let Some(api_key) = &model.api_key {
            headers.insert(
                reqwest::header::AUTHORIZATION,
                reqwest::header::HeaderValue::from_str(&format!("Bearer {}", api_key))
                    .map_err(|e| ServiceError::Header(e.to_string()))?
            );
        }
    }

    // Assicurati che ci sia l'header Content-Type: application/json
    if !headers.contains_key(reqwest::header::CONTENT_TYPE) {
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/json"),
        );
    }

    let request_json = serde_json::to_string(&request_body)?;

    for attempt in 0..config.api.retry_attempts {
        let response = client
            .post(&url)
            .headers(headers.clone())
            .body(request_json.clone())
            .send()
            .await;

        match response {
            Ok(resp) => {
                let status = resp.status();
                if resp.status().is_success() {
                    return Ok(resp.bytes().await?.to_vec());
                }
                eprintln!(
                    "[ERROR] Request failed (attempt {}/{}): {}",
                    attempt + 1,
                    config.api.retry_attempts,
                    resp.status()
                );
                if attempt == config.api.retry_attempts - 1 {
                    eprintln!("[ERROR] Response body: {}", resp.text().await.unwrap_or_default());
                    return Err(ServiceError::RequestFailed {
                        status,
                        message: String::from("Request failed after retries"),
                    });
                }
            },
            Err(e) => {
                eprintln!(
                    "[ERROR] Request error (attempt {}/{}): {}",
                    attempt + 1,
                    config.api.retry_attempts,
                    e
                );
                if attempt == config.api.retry_attempts - 1 {
                    return Err(ServiceError::Network(e));
                }
            }
        }
        if attempt < config.api.retry_attempts - 1 {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
    eprintln!("[ERROR] Max retry attempts reached");
    Err(ServiceError::RequestFailed {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        message: "Max retry attempts reached".to_string(),
    })
}

fn blake_128_concat(x: &[u8]) -> Vec<u8> {
    sp_core_hashing::blake2_128(x).iter().chain(x.iter()).cloned().collect::<Vec<_>>()
}

fn str_to_u256_vec(s: &str) -> Vec<u8> {
    let mut bytes = vec![0u8; 32];
    if let Ok(num) = u128::from_str_radix(s, 16) {
        for i in 0..16 {
            bytes[i] = (num >> (i * 8)) as u8;
        }
    }
    bytes
}

pub async fn call_chain_state_api(pallet: &str, storage: &str, key: &str) -> Result<Vec<u8>, ServiceError> {
    let config = get_config()?;
    let chain_url = config.api.chain_rpc_url
        .replace("ws://", "http://").replace("wss://", "https://");
    let client = Client::builder()
        .timeout(Duration::from_millis(config.api.timeout_ms))
        .use_rustls_tls()
        .build()?;
    // Build RPC request for state_getStorage
    let storage_key = format!("0x{}{}{}", 
        hex::encode(sp_core_hashing::twox_128(pallet.as_bytes())),
        hex::encode(sp_core_hashing::twox_128(storage.as_bytes())),
        if key.is_empty() { String::new() } else { hex::encode(
            blake_128_concat(&str_to_u256_vec(key)[..])
        ) }
    );
    let rpc_request = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "state_getStorage",
        "params": [storage_key],
        "id": 1
    });
    let response = client
        .post(&chain_url)
        .header("Content-Type", "application/json")
        .json(&rpc_request)
        .send()
        .await?;
    let status = response.status();
    if !response.status().is_success() {
        let err_msg = response.text().await.unwrap_or_default();
        eprintln!("[ERROR] Chain state API request failed: {}", err_msg);
        return Err(ServiceError::RequestFailed {
            status,
            message: err_msg,
        });
    }
    let result: serde_json::Value = response.json().await?;
    let storage_data = result["result"].as_str().unwrap_or("");
    if storage_data.is_empty() || storage_data == "null" {
        Ok(Vec::new())
    } else {
        Ok(hex::decode(storage_data.trim_start_matches("0x")).unwrap_or_default())
    }
}