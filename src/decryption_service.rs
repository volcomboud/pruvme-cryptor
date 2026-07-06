use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use serde_json::Value;
use crate::AppState;

#[derive(Debug,Deserialize)]
pub struct RequeteDecrypte {
    token_encrypte: String,
}
#[derive(Debug,Serialize, Deserialize)]
pub struct ReponseDecrypte {
    pub wallet_id: String,
    pub target_consumer_id: String,
    pub expiration: u64,
    pub claims: Value,
}
pub async fn service_decryption_handler(
    State(app_state): State<AppState>,
    Json(requete_payload): Json<RequeteDecrypte>
) -> Result<Json<ReponseDecrypte>, StatusCode> {
    println!("[SERVICE_DECRYPTION] request = {:?}", requete_payload);

    let chiffrement_chacha = obtenir_chiffrement(app_state)?;
    let decoded_base64_token = decode_base64_en_token(&requete_payload.token_encrypte)?;

    //Séparer le token pour extraire le nonce && le cipher_text -- nonce de 12 bytes
    let (nonce_extrait_bytes, cipher_text) = decoded_base64_token.split_at(12);
    let nonce_formate = extraire_nonce_from_bytes(nonce_extrait_bytes)?;

    let token_dechiffre = dechiffrer_token(nonce_formate, cipher_text, chiffrement_chacha)?;
    
    let token_decrypte_reponse = serde_json::from_str::<ReponseDecrypte>(&token_dechiffre).or_else(|_| {
        println!("[SERVICE_DECRYPTION] Erreur décryption");
        Err(StatusCode::INTERNAL_SERVER_ERROR)
    })?;
    Ok(Json::from(token_decrypte_reponse))
}

fn dechiffrer_token(nonce: Nonce, texte_chiffre: &[u8], chiffrement: ChaCha20Poly1305) -> Result<String, StatusCode> {
    let token_dechiffre_en_bytes = chiffrement.decrypt(&nonce, texte_chiffre).or_else(|_|{
        println!("[SERVICE_DECRYPTION] Le décryptage a échoué : Tag invalide ou Mauvaise Clé");
        Err(StatusCode::INTERNAL_SERVER_ERROR)
    })?;
    let token_dechiffre_en_string = String::from_utf8(token_dechiffre_en_bytes).or_else(|_|{
        Err(StatusCode::INTERNAL_SERVER_ERROR)
    })?;
    Ok(token_dechiffre_en_string)
}
fn extraire_nonce_from_bytes(nonce_en_bytes: &[u8]) -> Result<Nonce, StatusCode> {
    let nonce = Nonce::try_from(nonce_en_bytes).or_else(|_| {
        println!("[SERVICE_DECRYPTION] Le token n'a pas pu être décodé = {:?}", nonce_en_bytes);
        Err(StatusCode::BAD_REQUEST)
    })?;
    Ok(nonce)
}
fn decode_base64_en_token(base64_token: &str) -> Result<Vec<u8>,StatusCode> {
    let result = BASE64_URL_SAFE_NO_PAD.decode(base64_token).or_else( |_| {
        println!("[SERVICE_DECRYPTION] Le token n'a pas pu être décodé = {:?}", base64_token);
        Err(StatusCode::BAD_REQUEST)
    })?;
    Ok(result)
}
fn obtenir_chiffrement(app_state: AppState) -> Result<ChaCha20Poly1305, StatusCode> {
    let cha_cha_str = app_state.chacha_key;
    let key = Key::try_from(cha_cha_str).or_else(|_|{
        println!("[SERVICE_DECRYPTION] Probleme avec la clee de chiffrement: {:?}", cha_cha_str);
        Err(StatusCode::INTERNAL_SERVER_ERROR)
    })?;
    Ok(ChaCha20Poly1305::new(&key))
}