mod encryption_service;

use axum::{
    http::{Request, StatusCode},
    response::Response,
    body::Body,
    middleware::{self, Next},
    routing::{get, post},
    Router,
    extract::State,
    Json
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{time::Instant, sync::atomic::{AtomicI64, Ordering}, env};
use std::time::SystemTime;
use dotenvy::dotenv;

static  NEXT_REQUEST_ID: AtomicI64 = AtomicI64::new(1);
static  INTERNAL_HEADER_TOKEN: &str = "x-internal-token";

#[derive(Clone)]
pub struct AppState {
    pub chacha_key: [u8; 32],
}

// Faire un handler basic pour la requete
async fn hello_world() -> &'static str {
    "Hello, World!"
}

async fn authentification_static(req: Request<Body>, next: Next) -> Result<Response, StatusCode> {
    let x_internal_token = env::var("SECRET_TOKEN").unwrap_or_else(|err| {
        eprintln!("[ERROR] Variable d'environnement SECRET_TOKEN non définie. {}", err);
        std::process::exit(1);
    });
    let token_headers = req.headers().get(INTERNAL_HEADER_TOKEN);

    match token_headers {
        Some(token) if token == &x_internal_token => {
            Ok(next.run(req).await)
        }
        _ => {
            println!("[IN] NON-AUTORISE");
            Err(StatusCode::UNAUTHORIZED) },
    }
}

async fn logging_middleware(req: Request<Body>, next: Next) -> Result<Response, StatusCode> {
    let req_id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);

    let start_time = Instant::now();
    let method = req.method().clone();
    let uri = req.uri().clone();

    println!("[IN][REQ-{:?}] Request entrante : {:?} {:?} ", req_id, method, uri);

    let reponse = next.run(req).await;
    let duree_traitement_ms = start_time.elapsed();// .as_millis();
    let status = reponse.status();
    println!("[OUT][REQ-{:?}] Reponse traitement : {:?} {:?} {:?} Status: {:?}", req_id, duree_traitement_ms, method, uri, status);
    Ok(reponse)
}
//Ce macro dit a Rust de wrapper le program dans l'environnement Tokio
#[tokio::main]
async fn main () {
    dotenv().ok(); //charge les variable env contenu dans le fichiers env.
    let secret_chacha_key_str = env::var("CHACHA_KEY").unwrap_or_else(|_| {
        String::from("un-ultra-secure-32-byte-test-key")
    });

    let mut chacha_key = [0u8; 32];

    chacha_key.copy_from_slice(validater_chacha_key(&secret_chacha_key_str));

    let app_state = AppState {chacha_key};
    // Faire un Router pour exposer endpoint
    let app = Router::new()
        .route("/hello", get(hello_world))
        .route("/encrypte", post(encryption_service::encryption_service_handler))
        .with_state(app_state)
        .layer(middleware::from_fn(authentification_static))
        .layer(middleware::from_fn(logging_middleware));

    //Ouvrir un listener, ici on fait localhost port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();

    println!("Le server ouvert sur le port -> {:?}", listener.local_addr().unwrap());
    println!("\n -Ouvert GET /hello");
    println!("Url du server -> http://localhost:3000 ");

    axum::serve(listener, app).await.unwrap();
}


fn validater_chacha_key(secret_str: &String) -> &[u8] {
    let key_bytes = secret_str.as_bytes();
    if key_bytes.len() != 32 {
        eprintln!("[ERROR] Clee invalide, doit etre une String 32-bits.");
        std::process::exit( 1);
    }
    key_bytes
}