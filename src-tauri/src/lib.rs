use bytes::BytesMut;
use modules::objects::Keys;
use once_cell::sync::OnceCell;
use pqc_dilithium::*;
use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::{Ed25519KeyPair, KeyPair},
};
use std::env;
use std::fs::File;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tauri::{AppHandle, Manager as _};
use tauri::Wry;
use tokio::{io::AsyncWriteExt, net::TcpStream, sync::Mutex};
mod modules;
use futures::TryStreamExt;
use serde::{Deserialize, Serialize};
use sqlx::{migrate::MigrateDatabase, prelude::FromRow, sqlite::SqlitePoolOptions, Pool, Sqlite};
use std::io::{Read, Write};
use tauri::path::BaseDirectory;
use uuid::Uuid;

pub static GLOBAL_STORE: OnceCell<Mutex<Arc<tauri_plugin_store::Store<Wry>>>> = OnceCell::new();
pub static PROFILE_NAME: once_cell::sync::Lazy<Mutex<String>> = once_cell::sync::Lazy::new(|| Mutex::new(String::new()));

lazy_static::lazy_static! {
    pub static ref SHARED_SECRETS: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));
}
lazy_static::lazy_static! {
    pub static ref ENCRYPTION_KEY: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
}
lazy_static::lazy_static! {
    pub static ref GLOBAL_WRITE_HALF: Arc<Mutex<Option<tokio::io::WriteHalf<TcpStream>>>> = Arc::new(Mutex::new(None));
}
lazy_static::lazy_static! {
    pub static ref KEYS : Arc<Mutex<Option<modules::objects::Keys>>> = Arc::new(Mutex::new(None));
}
pub static GLOBAL_DB: OnceCell<Pool<Sqlite>> = OnceCell::new();


#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Chat {
    chat_id: String,
    chat_name: String,
    dst_user_id: String,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Message {
    message_id: String,
    chat_id: String,
    sender_id: String,
    message_type: String,
    content: String,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct KeysResponse {
    dilithium_public: Vec<u8>,
    dilithium_private: Vec<u8>,
    kyber_public: Vec<u8>,
    kyber_private: Vec<u8>,
    ed25519: Vec<u8>,
    nonce: Vec<u8>,
    user_id: String,
}

#[derive(Serialize, Deserialize)]
struct KeyStorage {
    dilithium_public: String,
    dilithium_private: String,
    kyber_public: String,
    kyber_private: String,
    ed25519: String,
    nonce: String,
    user_id: String,
    password_hash: String,
}

fn generate_pbkdf2_key(password: &str) -> Vec<u8>{
    let iterations = std::num::NonZeroU32::new(100_000).unwrap().get();

    const FIXED_SALT: &[u8] = b"this is my fixed salt!";

    let mut pbkdf2_key = [0u8; 32];
    pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(&password.as_bytes(), &FIXED_SALT, iterations, &mut pbkdf2_key).unwrap();
    pbkdf2_key.to_vec()
}
async fn create_and_write_json(
    handle: &tauri::AppHandle,
    keys: &KeysResponse,
    password: &str,
) -> Result<(), String> {

    let hashed_password = bcrypt::hash(password, bcrypt::DEFAULT_COST).expect("Failed to hash password");
    let file_name = PROFILE_NAME.lock().await.clone();
    let app_data_path = handle
        .path()
        .resolve(format!("{}.json", file_name), BaseDirectory::AppData)
        .map_err(|e| e.to_string())?;

    let data = KeyStorage {
        dilithium_public: hex::encode(keys.dilithium_public.clone()),
        kyber_public: hex::encode(keys.kyber_public.clone()),
        kyber_private: hex::encode(keys.kyber_private.clone()),
        dilithium_private: hex::encode(keys.dilithium_private.clone()),
        ed25519: hex::encode(keys.ed25519.clone()),
        nonce: hex::encode(keys.nonce.clone()),
        user_id: keys.user_id.clone(),
        password_hash: hashed_password.to_string()
    };

    let json_data = serde_json::to_string_pretty(&data).map_err(|e| e.to_string())?;

    let mut file = File::create(&app_data_path).map_err(|e| e.to_string())?;
    file.write_all(json_data.as_bytes())
        .map_err(|e| e.to_string())?;

    Ok(())
}
async fn load_keys(handle: &tauri::AppHandle, password: &str) -> Result<Keys, String> {
    let file_name = PROFILE_NAME.lock().await.clone();
    let app_data_path = handle
        .path()
        .resolve(format!("{}.json", file_name), BaseDirectory::AppData)
        .map_err(|e| e.to_string())?;

    let mut file = File::open(&app_data_path).map_err(|e| e.to_string())?;
    let mut json_data = String::new();
    file.read_to_string(&mut json_data)
        .map_err(|e| e.to_string())?;
    let data: KeyStorage = serde_json::from_str(&json_data).map_err(|e| e.to_string())?;

    let mut ed25519_array = [0u8; 83];
    ed25519_array.copy_from_slice(&hex::decode(data.ed25519).unwrap());
    let ed25519: Ed25519KeyPair = Ed25519KeyPair::from_pkcs8(&ed25519_array).unwrap();

    let mut d_public_key_array = [0u8; 1952];
    d_public_key_array.copy_from_slice(&hex::decode(data.dilithium_public).unwrap());

    let mut d_private_key_array = [0u8; 4000];
    d_private_key_array.copy_from_slice(&hex::decode(data.dilithium_private).unwrap());
    let dilithium_keypair = pqc_dilithium::Keypair::load(d_public_key_array, d_private_key_array);

    let mut nonce_array = [0u8; 16];
    nonce_array.copy_from_slice(&hex::decode(data.nonce).unwrap());

    let mut k_public_key_array = [0u8; 1568];
    k_public_key_array.copy_from_slice(&hex::decode(data.kyber_public).unwrap());

    let mut k_private_key_array = [0u8; 3168];
    k_private_key_array.copy_from_slice(&hex::decode(data.kyber_private).unwrap());
    let kyber_keys = pqc_kyber::Keypair {
        public: k_public_key_array,
        secret: k_private_key_array,
    };
    let is_valid = bcrypt::verify(password, &data.password_hash).expect("Failed to verify password");
    if is_valid {
        println!("Password is valid!");
    } else {
        println!("Invalid password!");
    }
    let keys = Keys {
        ed25519_keys: ed25519,
        dilithium_keys: dilithium_keypair,
        kyber_keys,
        nonce: nonce_array,
    };
    Ok(keys)
}

#[tauri::command]
async fn establish_ss(dst_user_id: String) {
    modules::tcp::send_kyber_key(hex::decode(dst_user_id).unwrap()).await;
}

#[tauri::command]
async fn send_message(dst_id_hexs: String, message_string: String) {
    let keys_lock = KEYS.lock().await;
    let keys = keys_lock.as_ref().expect("Keys not initialized");

    let dst_id_bytes = hex::decode(&dst_id_hexs).unwrap();

    let shared_secret = {
        let shared_secret_locked = SHARED_SECRETS.lock().await;
        println!("shared secret list {:?}", shared_secret_locked);
        shared_secret_locked.get(&dst_id_hexs).unwrap().clone()
    };

    let message = modules::encryption::encrypt_message(&message_string, &shared_secret).await;

    let dilithium_public_key = keys.dilithium_keys.public.clone();
    let ed25519_public_key = keys.ed25519_keys.public_key().as_ref().to_vec();

    let current_time = SystemTime::now();
    let duration_since_epoch = current_time
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");

    let timestamp = duration_since_epoch.as_secs() as u64;
    let timestamp_bytes = timestamp.to_le_bytes();

    let mut sign_part = BytesMut::with_capacity(
        dilithium_public_key.len()
            + ed25519_public_key.len()
            + dst_id_bytes.len()
            + keys.nonce.len()
            + timestamp_bytes.len()
            + message.len(),
    );
    sign_part.extend_from_slice(&dilithium_public_key);
    sign_part.extend_from_slice(&ed25519_public_key);
    sign_part.extend_from_slice(&dst_id_bytes);
    sign_part.extend_from_slice(&keys.nonce);
    sign_part.extend_from_slice(&timestamp_bytes);
    sign_part.extend_from_slice(&message);

    let dilithium_signature = keys.dilithium_keys.sign(&sign_part);
    let ed25519_signature = keys.ed25519_keys.sign(&sign_part).as_ref().to_vec();

    let mut buffer = BytesMut::with_capacity(
        5 + dilithium_signature.len() + ed25519_signature.len() + sign_part.len(),
    );

    buffer.extend_from_slice(&[0x04, 0x00, 0x00, 0x00, 0x00]);
    buffer.extend_from_slice(&dilithium_signature);
    buffer.extend_from_slice(&ed25519_signature);
    buffer.extend_from_slice(&sign_part);

    let total_size = buffer.len() as u16;
    buffer[1..3].copy_from_slice(&total_size.to_le_bytes());
    {
        let mut global_write_half = GLOBAL_WRITE_HALF.lock().await;
        let write_half = global_write_half.as_mut().unwrap();
        let _ = write_half.write_all(&buffer).await;
    }
    println!("Message sent");
}

#[tauri::command]
async fn generate_dilithium_keys(app: tauri::AppHandle, password: &str) -> Result<(), String> {
    match load_keys(&app, &password).await {
        Ok(keys) => {
            let full_hash_input = [
                &keys.dilithium_keys.public[..],
                &keys.ed25519_keys.public_key().as_ref()[..],
                &keys.nonce[..],
            ]
            .concat();
            let user_id = modules::utils::create_user_id_hash(&full_hash_input);
            {
                let mut key = ENCRYPTION_KEY.lock().await;
                *key = generate_pbkdf2_key(password);
            }
            println!("{}", user_id);
            {
                let mut keys_lock = KEYS.lock().await;
                *keys_lock = Some(keys);
            }
            let app_clone = app.clone();
            tokio::spawn(async move {
                let _ = modules::tcp::server_connect(&app_clone).await;
            });
            return Ok(());
        }
        _ => println!("error"),
    }

    let rng = SystemRandom::new();
    let mut kyber_rng = rand::rngs::OsRng;
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|_| "Failed to generate Ed25519 key pair".to_string())?;
    let ed25519_keys: Ed25519KeyPair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
        .map_err(|_| "Failed to parse Ed25519 key pair".to_string())?;

    let dilithium_keys: Keypair = Keypair::generate();
    let mut nonce = [0u8; 16];
    SecureRandom::fill(&rng, &mut nonce)
        .map_err(|_| "Failed to generate random bytes".to_string())?;

    let kyber_keys = pqc_kyber::keypair(&mut kyber_rng).unwrap();

    let full_hash_input = [
        &dilithium_keys.public[..],
        &ed25519_keys.public_key().as_ref()[..],
        &nonce[..],
    ]
    .concat();
    let user_id = modules::utils::create_user_id_hash(&full_hash_input);
    println!("{}", user_id);
    let keys = modules::objects::Keys {
        dilithium_keys,
        ed25519_keys,
        kyber_keys,
        nonce,
    };
    {
        let mut key = ENCRYPTION_KEY.lock().await;
        *key = generate_pbkdf2_key(password);
    }
    {
        let mut keys_lock = KEYS.lock().await;
        *keys_lock = Some(keys);
    }

    let app_clone = app.clone();
    tokio::spawn(async move {
        let _ = modules::tcp::server_connect(&app_clone).await;
    });

    let keys_response = KeysResponse {
        dilithium_public: dilithium_keys.public.to_vec(),
        dilithium_private: dilithium_keys.expose_secret().to_vec(),
        kyber_public: kyber_keys.public.to_vec(),
        kyber_private: kyber_keys.secret.to_vec(),
        ed25519: pkcs8_bytes.as_ref().to_vec(),
        nonce: nonce.to_vec(),
        user_id,
    };
    create_and_write_json(&app.clone(), &keys_response, password).await.unwrap();

    Ok(())
}

async fn setup_app_state(app: &tauri::AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    let db = setup_db(app).await;
    GLOBAL_DB
        .set(db.clone())
        .expect("Failed to set global DB. It may have been set already.");
    app.manage(modules::objects::AppState { db });
    println!("Successfully initialised DB");
    Ok(())
}

pub async fn setup_db(app: &AppHandle) -> modules::objects::Db {
    let mut path = app.path().app_data_dir().expect("failed to get data_dir");
    println!("{:?}", &path);

    match std::fs::create_dir_all(path.clone()) {
        Ok(_) => {}
        Err(err) => {
            panic!("error creating directory {}", err);
        }
    };

    path.push("db.sqlite");

    Sqlite::create_database(
        format!(
            "sqlite:{}",
            path.to_str().expect("path should be something")
        )
        .as_str(),
    )
    .await
    .expect("failed to create database");

    let db = SqlitePoolOptions::new()
        .connect(path.to_str().unwrap())
        .await
        .unwrap();

    sqlx::migrate!("./migrations").run(&db).await.unwrap();

    db
}

#[tauri::command]
async fn get_chats(state: tauri::State<'_, modules::objects::AppState>) -> Result<Vec<Chat>, String> {
    let db = &state.db;
    let current_profile = modules::utils::get_profile_name().await;
    let chats: Vec<Chat> = sqlx::query_as::<_, Chat>("SELECT * FROM chats WHERE chat_profil = ?1 ORDER BY last_updated DESC")
        .bind(current_profile)
        .fetch(db)
        .try_collect()
        .await
        .map_err(|e| format!("Failed to get chats: {}", e))?;

    Ok(chats)
}

#[tauri::command]
async fn save_message(
    state: tauri::State<'_, modules::objects::AppState>,
    sender_id: &str,
    message: String,
    message_type: &str,
) -> Result<(), String> {
    let db = &state.db;
    let key = ENCRYPTION_KEY.lock().await;

    let encrypted_message_vec = modules::encryption::encrypt_message(&message, &key).await;
    let encrypted_message = hex::encode(encrypted_message_vec);

    let current_time = chrono::Utc::now().timestamp();

    let chat_id: String = sqlx::query_scalar("SELECT chat_id FROM chats WHERE dst_user_id = ?")
        .bind(sender_id)
        .fetch_one(db)
        .await
        .map_err(|e| format!("Failed to get chat_id: {}", e))?;

    sqlx::query("UPDATE chats SET last_updated = ? WHERE chat_id = ?")
        .bind(&current_time)
        .bind(&chat_id)
        .execute(db)
        .await
        .map_err(|e| format!("Error updating shared secret: {}", e))?;

    let message_id = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO messages (message_id, sender_id, message_type, content, chat_id) VALUES (?1, ?2, ?3, ?4, ?5)")
        .bind(message_id)
        .bind(sender_id)
        .bind(message_type)
        .bind(encrypted_message)
        .bind(chat_id)
        .execute(db)
        .await
        .map_err(|e| format!("Error saving todo: {}", e))?;
    Ok(())
}

#[tauri::command]
async fn get_messages(
    state: tauri::State<'_, modules::objects::AppState>,
    chat_id: &str,
) -> Result<Vec<Message>, String> {
    let db = &state.db;
    
    let key = ENCRYPTION_KEY.lock().await;
    println!("{:?}", key);
    
    let messages: Vec<Message> =
        sqlx::query_as::<_, Message>("SELECT * FROM messages WHERE chat_id = ?1")
            .bind(chat_id)
            .fetch(db)
            .try_collect()
            .await
            .map_err(|e| format!("Failed to get messages: {}", e))?;
    println!("{:?}", &messages);
        let mut decrypted_messages = Vec::new();
        for mut msg in messages {
            let encrypted_buffer = hex::decode(msg.content).unwrap();
    
            match modules::encryption::decrypt_message(&encrypted_buffer, &key).await {
                Ok(decrypted) => {
                    println!("{}", &decrypted);
                    msg.content = decrypted;
                    decrypted_messages.push(msg);
                }
                Err(_) => return Err("Decryption failed".into()),
            }
        }
    Ok(decrypted_messages)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_store::Builder::default().build())
        .invoke_handler(tauri::generate_handler![
            generate_dilithium_keys,
            send_message,
            modules::database::add_chat,
            get_chats,
            save_message,
            get_messages,
            modules::database::has_shared_secret,
            establish_ss,
            modules::database::set_profile_name,
            modules::database::delete_chat,
            modules::database::create_profil,
            modules::database::load_shared_secrets
        ])
        .setup(|app| {
            let app_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                if let Err(e) = setup_app_state(&app_handle).await {
                    eprintln!("Error setting up app state: {}", e);
                }
            });
            Ok(())
        })
        .plugin(tauri_plugin_opener::init())
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}