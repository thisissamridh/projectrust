// main.rs
use actix_web::{App, HttpResponse, HttpServer, web};
use base58::{FromBase58, ToBase58};
use base64;
use ed25519_dalek::{
    Keypair as DalekKeypair, PublicKey as DalekPubkey, Signature as DalekSignature,
    Signer as DalekSigner, Verifier,
};
use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signer::{Signer, keypair::Keypair};
use solana_sdk::system_instruction;
use spl_associated_token_account::get_associated_token_address;
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
struct KeypairData {
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
struct InstructionResponse {
    program_id: String,
    accounts: Vec<Account>,
    instruction_data: String,
}

#[derive(Deserialize)]
struct TokenMintRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct SignMessageResponse {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyMessageResponse {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Serialize)]
struct SendSolResponse {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct TokenAccount {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
}

#[derive(Serialize)]
struct SendTokenResponse {
    program_id: String,
    accounts: Vec<TokenAccount>,
    instruction_data: String,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Starting server on http://0.0.0.0:8080");
    HttpServer::new(|| {
        App::new()
            .route("/health", web::get().to(health))
            .route("/keypair", web::post().to(make_keypair))
            .route("/token/create", web::post().to(make_token))
            .route("/token/mint", web::post().to(mint_token))
            .route("/message/sign", web::post().to(sign_message))
            .route("/message/verify", web::post().to(verify_message))
            .route("/send/sol", web::post().to(send_sol))
            .route("/send/token", web::post().to(send_token))
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}

async fn health() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({ "status": "ok" }))
}

async fn make_keypair() -> HttpResponse {
    let kp = Keypair::new();
    let data = KeypairData {
        pubkey: kp.pubkey().to_string(),
        secret: kp.to_bytes().to_base58(),
    };
    HttpResponse::Ok().json(Response {
        success: true,
        data: Some(data),
        error: None,
    })
}

async fn make_token(req: web::Json<TokenCreateRequest>) -> HttpResponse {
    if req.mint_authority.is_empty() || req.mint.is_empty() {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Missing required fields".to_string()),
        });
    }

    if req.decimals > 9 {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Decimals must be between 0 and 9".to_string()),
        });
    }

    let mint_auth = Pubkey::from_str(&req.mint_authority)
        .map_err(|_| {
            HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid mint authority".to_string()),
            })
        })
        .unwrap();
    let mint_addr = Pubkey::from_str(&req.mint)
        .map_err(|_| {
            HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid mint address".to_string()),
            })
        })
        .unwrap();

    let ix =
        instruction::initialize_mint(&spl_token::id(), &mint_addr, &mint_auth, None, req.decimals)
            .map_err(|_| {
                HttpResponse::BadRequest().json(Response::<()> {
                    success: false,
                    data: None,
                    error: Some("Instruction creation failed".to_string()),
                })
            })
            .unwrap();

    let accounts = ix
        .accounts
        .iter()
        .map(|acc| Account {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    HttpResponse::Ok().json(Response {
        success: true,
        data: Some(InstructionResponse {
            program_id: ix.program_id.to_string(),
            accounts,
            instruction_data: base64::encode(&ix.data),
        }),
        error: None,
    })
}

async fn mint_token(req: web::Json<TokenMintRequest>) -> HttpResponse {
    if req.amount == 0
        || req.mint.is_empty()
        || req.destination.is_empty()
        || req.authority.is_empty()
    {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Invalid input".to_string()),
        });
    }

    let mint = Pubkey::from_str(&req.mint).unwrap();
    let destination = Pubkey::from_str(&req.destination).unwrap();
    let authority = Pubkey::from_str(&req.authority).unwrap();

    let ix = instruction::mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        req.amount,
    )
    .unwrap();

    let accounts = ix
        .accounts
        .iter()
        .map(|acc| Account {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    HttpResponse::Ok().json(Response {
        success: true,
        data: Some(InstructionResponse {
            program_id: ix.program_id.to_string(),
            accounts,
            instruction_data: base64::encode(&ix.data),
        }),
        error: None,
    })
}

async fn sign_message(req: web::Json<SignMessageRequest>) -> HttpResponse {
    if req.message.is_empty() || req.secret.is_empty() {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Missing fields".to_string()),
        });
    }

    let secret_bytes = match req.secret.from_base58() {
        Ok(b) if b.len() == 64 => b,
        _ => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid secret".to_string()),
            });
        }
    };

    let keypair = DalekKeypair::from_bytes(&secret_bytes).unwrap();
    let sig = keypair.sign(req.message.as_bytes());

    HttpResponse::Ok().json(Response {
        success: true,
        data: Some(SignMessageResponse {
            signature: base64::encode(sig.to_bytes()),
            public_key: keypair.public.to_bytes().to_base58(),
            message: req.message.clone(),
        }),
        error: None,
    })
}

async fn verify_message(req: web::Json<VerifyMessageRequest>) -> HttpResponse {
    if req.message.is_empty() || req.signature.is_empty() || req.pubkey.is_empty() {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Missing fields".to_string()),
        });
    }

    let pubkey_bytes = match req.pubkey.from_base58() {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid pubkey".to_string()),
            });
        }
    };

    let signature_bytes = match base64::decode(&req.signature) {
        Ok(bytes) if bytes.len() == 64 => bytes,
        _ => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid signature".to_string()),
            });
        }
    };

    let pk = DalekPubkey::from_bytes(&pubkey_bytes).unwrap();
    let sig = DalekSignature::from_bytes(&signature_bytes).unwrap();
    let valid = pk.verify(req.message.as_bytes(), &sig).is_ok();

    HttpResponse::Ok().json(Response {
        success: true,
        data: Some(VerifyMessageResponse {
            valid,
            message: req.message.clone(),
            pubkey: req.pubkey.clone(),
        }),
        error: None,
    })
}

async fn send_sol(req: web::Json<SendSolRequest>) -> HttpResponse {
    if req.from == req.to || req.lamports == 0 {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Invalid transfer".to_string()),
        });
    }

    let from = Pubkey::from_str(&req.from).unwrap();
    let to = Pubkey::from_str(&req.to).unwrap();
    let ix = system_instruction::transfer(&from, &to, req.lamports);
    let accounts = ix
        .accounts
        .iter()
        .map(|acc| acc.pubkey.to_string())
        .collect();

    HttpResponse::Ok().json(Response {
        success: true,
        data: Some(SendSolResponse {
            program_id: ix.program_id.to_string(),
            accounts,
            instruction_data: base64::encode(&ix.data),
        }),
        error: None,
    })
}

async fn send_token(req: web::Json<SendTokenRequest>) -> HttpResponse {
    if req.amount == 0
        || req.destination.is_empty()
        || req.owner.is_empty()
        || req.mint.is_empty()
        || req.owner == req.destination
    {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Invalid input".to_string()),
        });
    }

    let mint = Pubkey::from_str(&req.mint).unwrap();
    let owner = Pubkey::from_str(&req.owner).unwrap();
    let destination = Pubkey::from_str(&req.destination).unwrap();

    let source = get_associated_token_address(&owner, &mint);
    let dest = get_associated_token_address(&destination, &mint);

    let ix =
        instruction::transfer(&spl_token::id(), &source, &dest, &owner, &[], req.amount).unwrap();
    let accounts = ix
        .accounts
        .iter()
        .map(|acc| TokenAccount {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
        })
        .collect();

    HttpResponse::Ok().json(Response {
        success: true,
        data: Some(SendTokenResponse {
            program_id: ix.program_id.to_string(),
            accounts,
            instruction_data: base64::encode(&ix.data),
        }),
        error: None,
    })
}
