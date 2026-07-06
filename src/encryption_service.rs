use std::time::SystemTime;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::AppState;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use base64::{
    engine::general_purpose::URL_SAFE_NO_PAD, Engine as _
};
use chacha20poly1305::aead::Generate;

#[derive(Debug,Deserialize)]
pub struct RequeteEncrypte {
    pub wallet_id: String,
    pub target_consumer_id: String,
    pub claims: Value,
}
#[derive(Debug,Serialize)]
pub struct ReponseEncrypte {
    pub token_encrypte: String,
    pub expiration_date: u64,
}
#[derive(Debug,Serialize)]
pub struct  EnveloppeSecure {
    pub wallet_id: String,
    pub target_consumer_id: String,
    pub expiration: u64,
    pub claims: Value,
}
pub async fn service_encryption_handler(
    State(app_state): State<AppState>,
    Json(requete_payload): Json<RequeteEncrypte>
) -> Result<Json<ReponseEncrypte>, StatusCode> {
    println!("[IN] Requete recu pour l'identifiant portefeuille : {:?}", requete_payload.wallet_id);

//########################## Preparation des donnee
    // 300 (seconde) == 5 minutes || changer pour quelque chose de plus sérieux
    let delai_expiration= obtenir_delai_expiration_epoch(300);
    let enveloppe_securite = json_payload_to_enveloppe(requete_payload, delai_expiration);
    let donnee_pret_pour_encryption = enveloppe_to_bytes(&enveloppe_securite)?;

    let donnee_encrypte = bytes_to_token_encrypte(donnee_pret_pour_encryption, app_state.chacha_key)?;

    Ok(Json(ReponseEncrypte {
        token_encrypte: donnee_encrypte,
        expiration_date: delai_expiration,
    }))
}

fn bytes_to_token_encrypte(raw_bytes: Vec<u8>, chacha_key: [u8; 32]) -> Result<String,StatusCode> {
    let key= Key::try_from(chacha_key).unwrap();
    let cipher = ChaCha20Poly1305::new(&key);

    let nonce= Nonce::generate();

    println!("[SERVICE_ENCRYPTION] Nonce: {:?}", nonce);
    println!("[SERVICE_ENCRYPTION] Raw_bytes: {:?}", raw_bytes);

    let cyphertext = cipher.encrypt(&nonce, raw_bytes.as_slice()).or_else(|err| {
        println!("[SERVICE_ENCRYPTION] Erreur lors de l'encryption des données: {:?}", err);
        Err(StatusCode::INTERNAL_SERVER_ERROR)
    });

    //TEST
    let cipher_test = cyphertext.as_ref().clone().unwrap();
    let test = cipher.decrypt(&nonce, cipher_test.as_slice());
    println!("[SERVICE_ENCRYPTION] Cypher_text: {:?}", cyphertext);
    println!("[SERVICE_ENCRYPTION] test bytes: {:?}", test);
    let test_2 = String::from_utf8(test.unwrap().to_vec());
    println!("[SERVICE_ENCRYPTION] test string: {:?}", test_2);
//FIN TEST

    let mut donne_combine = nonce.to_vec();
    donne_combine.append(&mut cyphertext.unwrap());
    //donne_combine.extend_from_slice(&cyphertext.unwrap());

    let token_encrypte = URL_SAFE_NO_PAD.encode(&donne_combine);
    println!("[SERVICE_ENCRYPTION] Information encryptée avec succès");

    // =================================================================
    // TEST ÉDUCATIF : DÉCRYPTAGE DEPUIS LA CHAÎNE BASE64
    // =================================================================
    print!("[SERVICE_ENCRYPTION] token_encrypte: {:?}" , token_encrypte);
    // 1. Décoder la chaîne Base64 pour retrouver nos octets bruts (combined_data)
    let decoded_bytes = URL_SAFE_NO_PAD.decode(&token_encrypte).expect("Erreur de décodage Base64");
    // 2. Séparer le Nonce public (12 octets) du reste (Ciphertext + Tag)
    // split_at(12) coupe littéralement le tableau en deux à l'index 12.
    let (test_nonce_bytes, test_ciphertext_bytes) = decoded_bytes.split_at(12);
    // 3. Reconstruire l'objet Nonce attendu par ChaCha20
   // let test_nonce = Nonce::from_slice(test_nonce_bytes);
    let test_nonce = Nonce::try_from(test_nonce_bytes).unwrap();
    // 4. Décrypter ! (C'est ici que Poly1305 vérifie aussi que rien n'a été altéré)
    let test_decrypted_bytes = cipher.decrypt(&test_nonce, test_ciphertext_bytes)
        .expect("Le décryptage a échoué (Tag invalide ou mauvaise clé) !");
    // 5. Reconvertir les octets bruts en chaîne de caractères lisible (UTF-8)
    let test_decrypted_string = String::from_utf8(test_decrypted_bytes).unwrap();
    println!("[TEST] Succès ! Voici le JSON décrypté : {}", test_decrypted_string);
    // ===================================================
    Ok(token_encrypte)
}
fn enveloppe_to_bytes(enveloppe_secure: &EnveloppeSecure) -> Result<Vec<u8>, StatusCode> {
    let raw_json_to_string = serde_json::to_string(&enveloppe_secure).or_else(|err| {
        println!("[SERVICE_ENCRYPTION] Erreur de serialisation: {:?}", err);
        Err(StatusCode::INTERNAL_SERVER_ERROR)
    });
    let bytes_pour_encryption = raw_json_to_string?.into_bytes();
     Ok(bytes_pour_encryption)
}
fn json_payload_to_enveloppe(json_payload: RequeteEncrypte, delai_expiration: u64) -> EnveloppeSecure {
    EnveloppeSecure {
        wallet_id: json_payload.wallet_id,
        target_consumer_id: json_payload.target_consumer_id,
        expiration: delai_expiration,
        claims: json_payload.claims
    }
}
fn obtenir_delai_expiration_epoch(delai_ajoute: u64) -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + delai_ajoute
}