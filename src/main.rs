use actix_web::{App, HttpResponse, HttpServer, web};
use base58::ToBase58;
use base64;
use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signer::{Signer, keypair::Keypair};
use spl_token::instruction;
use std::str::FromStr;

#[derive(Serialize)]
struct Response<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct Keypair_Data {
    pubkey: String,
    secret: String,
}

#[derive(Deserialize)]
struct TokenCreateRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Serialize)]
struct Account {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct TokenCreateResponse {
    program_id: String,
    accounts: Vec<Account>,
    instruction_data: String,
}

async fn make_keypair() -> HttpResponse {
    let kp = Keypair::new();

    let data = Keypair_Data {
        pubkey: kp.pubkey().to_string(),
        secret: kp.to_bytes().to_base58(),
    };

    let resp = Response {
        success: true,
        data: Some(data),
        error: None,
    };

    HttpResponse::Ok().json(resp)
}

async fn make_token(req: web::Json<TokenCreateRequest>) -> HttpResponse {
    // check if pubkeys are valid
    let mint_auth = match Pubkey::from_str(&req.mint_authority) {
        Ok(pk) => pk,
        Err(_) => {
            let resp = Response::<()> {
                success: false,
                data: None,
                error: Some("bad mint authority".to_string()),
            };
            return HttpResponse::BadRequest().json(resp);
        }
    };

    let mint_addr = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => {
            let resp = Response::<()> {
                success: false,
                data: None,
                error: Some("bad mint address".to_string()),
            };
            return HttpResponse::BadRequest().json(resp);
        }
    };

    // make the instruction
    let ix =
        instruction::initialize_mint(&spl_token::id(), &mint_addr, &mint_auth, None, req.decimals)
            .unwrap();

    let mut accounts = Vec::new();
    for acc in ix.accounts {
        accounts.push(Account {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        });
    }

    let data = TokenCreateResponse {
        program_id: ix.program_id.to_string(),
        accounts: accounts,
        instruction_data: base64::encode(&ix.data),
    };

    let resp = Response {
        success: true,
        data: Some(data),
        error: None,
    };

    HttpResponse::Ok().json(resp)
}

async fn health() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok"
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Starting server on port 8080");

    HttpServer::new(|| {
        App::new()
            .route("/health", web::get().to(health))
            .route("/keypair", web::post().to(make_keypair))
            .route("/token/create", web::post().to(make_token))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
