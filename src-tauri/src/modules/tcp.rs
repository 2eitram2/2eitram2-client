use super::handle;
use bytes::{Buf,BytesMut};
use ring::signature::KeyPair;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::AppHandle;
use tokio::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn server_connect(app: &AppHandle) -> io::Result<()> {
    let stream = TcpStream::connect("192.168.1.51:8081").await?;
    let (mut read_half, mut write_half) = tokio::io::split(stream);

    let keys_lock = super::super::KEYS.lock().await;
    let keys = keys_lock.as_ref().expect("Keys not initialized");

    let dilithium_public_key = &keys.dilithium_keys.public;
    let ed25519_public_key = keys.ed25519_keys.public_key().as_ref();

    let current_time = SystemTime::now();
    let duration_since_epoch = current_time
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    let timestamp = duration_since_epoch.as_secs().to_le_bytes();

    let mut sign_part = BytesMut::with_capacity(
        dilithium_public_key.len() + ed25519_public_key.len() + keys.nonce.len() + timestamp.len(),
    );
    sign_part.extend_from_slice(dilithium_public_key);
    sign_part.extend_from_slice(ed25519_public_key);
    sign_part.extend_from_slice(&keys.nonce);
    sign_part.extend_from_slice(&timestamp);

    let dilithium_signature = keys.dilithium_keys.sign(&sign_part);
    let ed25519_signature = keys.ed25519_keys.sign(&sign_part).as_ref().to_vec();
    drop(keys_lock);
    let mut buffer = BytesMut::with_capacity(
        5 + dilithium_signature.len() + ed25519_signature.len() + sign_part.len(),
    );
    buffer.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00]);
    buffer.extend_from_slice(&dilithium_signature);
    buffer.extend_from_slice(&ed25519_signature);
    buffer.extend_from_slice(&sign_part);

    let total_size = buffer.len() as u16;
    buffer[1..3].copy_from_slice(&total_size.to_le_bytes());

    write_half.write_all(&buffer).await?;

    {
        let mut global_write_half = super::super::GLOBAL_WRITE_HALF.lock().await;
        *global_write_half = Some(write_half);
    }

    listen(&mut read_half, app).await?;

    Ok(())
}

pub async fn send_cyphertext(dst_id_bytes: Vec<u8>, cyphertext: Vec<u8>) -> Vec<u8> {
    let keys_lock = super::super::KEYS.lock().await;
    let keys = keys_lock.as_ref().expect("Keys not initialized");

    let dilithium_public_key = keys.dilithium_keys.public.clone();
    let ed25519_public_key = keys.ed25519_keys.public_key().as_ref().to_vec();
    let nonce = keys.nonce;
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
            + nonce.len()
            + timestamp_bytes.len()
            + cyphertext.len(),
    );
    sign_part.extend_from_slice(&dilithium_public_key);
    sign_part.extend_from_slice(&ed25519_public_key);
    sign_part.extend_from_slice(&dst_id_bytes);
    sign_part.extend_from_slice(&nonce);
    sign_part.extend_from_slice(&timestamp_bytes);
    sign_part.extend_from_slice(&cyphertext);

    let dilithium_signature = keys.dilithium_keys.sign(&sign_part);
    let ed25519_signature = keys.ed25519_keys.sign(&sign_part).as_ref().to_vec();
    drop(keys_lock);

    let mut buffer = BytesMut::with_capacity(
        5 + dilithium_signature.len() + ed25519_signature.len() + sign_part.len(),
    );

    buffer.extend_from_slice(&[0x03, 0x00, 0x00, 0x00, 0x00]);
    buffer.extend_from_slice(&dilithium_signature);
    buffer.extend_from_slice(&ed25519_signature);
    buffer.extend_from_slice(&sign_part);

    let total_size = buffer.len() as u16;
    buffer[1..3].copy_from_slice(&total_size.to_le_bytes());
    buffer.to_vec()
}

pub async fn send_kyber_key(dst_id_bytes: Vec<u8>) {
    let keys_lock = super::super::KEYS.lock().await;
    let keys = keys_lock.as_ref().expect("Keys not initialized");
    let kyber_public_key = keys.kyber_keys.public;
    let dilithium_public_key = keys.dilithium_keys.public.clone();
    let ed25519_public_key = keys.ed25519_keys.public_key().as_ref().to_vec();
    let nonce = keys.nonce;
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
            + nonce.len()
            + timestamp_bytes.len()
            + kyber_public_key.len(),
    );
    sign_part.extend_from_slice(&dilithium_public_key);
    sign_part.extend_from_slice(&ed25519_public_key);
    sign_part.extend_from_slice(&dst_id_bytes);
    sign_part.extend_from_slice(&nonce);
    sign_part.extend_from_slice(&timestamp_bytes);
    sign_part.extend_from_slice(&kyber_public_key);

    let dilithium_signature = keys.dilithium_keys.sign(&sign_part);
    let ed25519_signature = keys.ed25519_keys.sign(&sign_part).as_ref().to_vec();
    drop(keys_lock);

    let mut buffer = BytesMut::with_capacity(
        5 + dilithium_signature.len() + ed25519_signature.len() + sign_part.len(),
    );

    buffer.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00]);
    buffer.extend_from_slice(&dilithium_signature);
    buffer.extend_from_slice(&ed25519_signature);
    buffer.extend_from_slice(&sign_part);

    let total_size = buffer.len() as u16;
    buffer[1..3].copy_from_slice(&total_size.to_le_bytes());
    {
        let mut global_write_half = super::super::GLOBAL_WRITE_HALF.lock().await;
        let write_half =  global_write_half.as_mut().unwrap();
        let _ = write_half.write_all(&buffer.to_vec()).await;
        println!("Sent kyber");
    }
}

async fn listen(
    read_half: &mut tokio::io::ReadHalf<tokio::net::TcpStream>,
    app: &AppHandle,
) -> io::Result<()> {
    let mut buffer = BytesMut::with_capacity(1024);
    let mut chunk = vec![0u8; 1024];
    loop {
        match read_half.read(&mut chunk).await {
            Ok(0) => {
                println!("Disconnected from server.");
                break;
            }
            Ok(n) => {
                buffer.extend_from_slice(&chunk[..n]);

                if buffer.len() < 3 {
                    println!("[ERROR] Invalid packet: too short");
                    buffer.clear();
                    continue;
                }

                let prefix = buffer[0];
                let payload_size_bytes = &buffer[1..3];
                let payload_size =
                    u16::from_le_bytes([payload_size_bytes[0], payload_size_bytes[1]]) as usize;

                if buffer.len() < payload_size {
                    continue;
                }

                match prefix {
                    2 => {
                        let response = super::handle::handle_kyber(&buffer[..payload_size].to_vec()).await.unwrap();
                        {
                            let mut global_write_half = super::super::GLOBAL_WRITE_HALF.lock().await;
                            let write_half = global_write_half.as_mut().unwrap();
                            write_half.write_all(&response).await?;
                        }
                    }
                    3 => {
                        if let Err(err) = handle::handle_ct(&buffer[..payload_size].to_vec()).await {
                            println!("Error handling ciphertext: {}", err);
                        }                        
                    }
                    4 => {
                        println!("{}", buffer.len());
                        let _ = handle::handle_message(&buffer[..payload_size].to_vec(), app).await;
                    }
                    _ => {
                        println!("[ERROR] Invalid packet: unknown prefix {}", prefix);
                    }
                }

                buffer.advance(payload_size);
                
            }
            Err(e) => {
                eprintln!("Error reading from stream: {:?}", e);
                break;
            }
        }
    }

    Ok(())
}
