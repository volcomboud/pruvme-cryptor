use std::time::SystemTime;
use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::AppState;

#[derive(Debug,Deserialize)]
pub struct RequeteEncrypte {
    pub wallet_id: String,
    pub target_consumer_id: String,
    pub claims: Value,
}
#[derive(Debug,Serialize)]
pub struct  EnveloppeSecure {
    pub sub: String,
    pub audience: String,
    pub expiration: u64,
    pub claims: Value,
}
#[derive(Debug,Serialize)]
pub struct ReponseEncrypte {
    pub token_encrypte: String,
    pub expiration_date: u64,
}
pub async fn encryption_service_handler(
    State(state): State<AppState>,
    Json(payload): Json<RequeteEncrypte>
) -> Json<ReponseEncrypte> {
    println!("[IN] Requete recu pour l'identifiant portefeuille : {:?}", payload.wallet_id);

    // Faire l'enveloppe de securite
    let delai_expiration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 300; // ~5 minutes changer pour quelque chose de plus sérieux mais pour l'instant 5 minutes

    let enveloppe_securite = EnveloppeSecure {
        sub: payload.wallet_id,
        audience: payload.target_consumer_id,
        expiration: delai_expiration,
        claims: payload.claims
    };
    
    Json(ReponseEncrypte {
        token_encrypte: String::from("On renvoi un healthy truc muche"),
        expiration_date: delai_expiration,
    })
}