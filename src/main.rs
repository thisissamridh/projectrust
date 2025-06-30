use actix_web::{App, HttpResponse, HttpServer, web};
use base58::{FromBase58, ToBase58};
use base64;
use bincode;
use serde::{Deserialize, Serialize};
use solana_sdk::{
    hash::Hash,
    message::Message,
    pubkey::Pubkey,
    signer::{Signer, keypair::Keypair},
    system_instruction,
    transaction::Transaction,
};
use spl_associated_token_account::get_associated_token_address;
use spl_token::instruction;
use std::str::FromStr;

use ed25519_dalek::{
    Keypair as DalekKeypair, PublicKey as DalekPubkey, Signature as DalekSignature, Signer as _,
    Verifier as _,
};

/// Generic JSON response wrapper
#[derive(Serialize)]
struct Response<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Data returned by `/keypair`
#[derive(Serialize)]
struct KeypairData {
    pubkey: String,
    secret: String,
}

/// Instruction-only response meta
#[derive(Serialize)]
struct AccountMetaInfo {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct InstructionResponse {
    program_id: String,
    accounts: Vec<AccountMetaInfo>,
    instruction_data: String,
}

/// Payload for build-only RPC transactions
#[derive(Serialize)]
struct TxPayload {
    /// Base64-encoded serialized Transaction
    transaction: String,
}

/// `/token/create` request
#[derive(Deserialize)]
struct TokenCreateRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

/// `/token/mint` request
#[derive(Deserialize)]
struct TokenMintRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

/// `/message/sign` request
#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

/// `/message/sign` response
#[derive(Serialize)]
struct SignMessageResponse {
    signature: String,
    public_key: String,
    message: String,
}

/// `/message/verify` request
#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

/// `/message/verify` response
#[derive(Serialize)]
struct VerifyMessageResponse {
    valid: bool,
    message: String,
    pubkey: String,
}

/// `/send/sol` request
#[derive(Deserialize)]
struct SendSolRequest {
    /// Base58 recent blockhash
    recent_blockhash: String,
    /// Base58 secret key for fee-payer & signer
    secret: String,
    /// Recipient pubkey
    to: String,
    /// lamports
    lamports: u64,
}

/// `/send/token` request
#[derive(Deserialize)]
struct SendTokenRequest {
    recent_blockhash: String,
    secret: String,
    owner: String,
    mint: String,
    destination: String,
    amount: u64,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Starting server on http://0.0.0.0:8080");
    HttpServer::new(|| {
        App::new()
            .route("/health", web::get().to(health))
            .route("/keypair", web::post().to(make_keypair))
            .route("/token/create", web::post().to(create_token_instruction))
            .route("/token/mint", web::post().to(mint_token_instruction))
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

async fn create_token_instruction(req: web::Json<TokenCreateRequest>) -> HttpResponse {
    if req.mint_authority.is_empty() || req.mint.is_empty() {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Missing required fields".into()),
        });
    }
    if req.decimals > 9 {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Decimals must be ≤ 9".into()),
        });
    }

    let mint_auth = match Pubkey::from_str(&req.mint_authority) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid mintAuthority".into()),
            });
        }
    };
    let mint_addr = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid mint".into()),
            });
        }
    };

    let ix = match instruction::initialize_mint(
        &spl_token::id(),
        &mint_addr,
        &mint_auth,
        None,
        req.decimals,
    ) {
        Ok(ix) => ix,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Failed to build initialize_mint".into()),
            });
        }
    };

    let accounts = ix
        .accounts
        .into_iter()
        .map(|acc| AccountMetaInfo {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    let resp = InstructionResponse {
        program_id: ix.program_id.to_string(),
        accounts,
        instruction_data: base64::encode(&ix.data),
    };
    HttpResponse::Ok().json(Response {
        success: true,
        data: Some(resp),
        error: None,
    })
}

async fn mint_token_instruction(req: web::Json<TokenMintRequest>) -> HttpResponse {
    if req.mint.is_empty() || req.destination.is_empty() || req.authority.is_empty() {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Missing required fields".into()),
        });
    }
    if req.amount == 0 {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Amount must be > 0".into()),
        });
    }

    let mint_addr = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid mint".into()),
            });
        }
    };
    let dest_addr = match Pubkey::from_str(&req.destination) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid destination".into()),
            });
        }
    };
    let auth_addr = match Pubkey::from_str(&req.authority) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid authority".into()),
            });
        }
    };

    let ix = match instruction::mint_to(
        &spl_token::id(),
        &mint_addr,
        &dest_addr,
        &auth_addr,
        &[],
        req.amount,
    ) {
        Ok(ix) => ix,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Failed to build mint_to".into()),
            });
        }
    };

    let accounts = ix
        .accounts
        .into_iter()
        .map(|acc| AccountMetaInfo {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    let resp = InstructionResponse {
        program_id: ix.program_id.to_string(),
        accounts,
        instruction_data: base64::encode(&ix.data),
    };
    HttpResponse::Ok().json(Response {
        success: true,
        data: Some(resp),
        error: None,
    })
}

async fn sign_message(req: web::Json<SignMessageRequest>) -> HttpResponse {
    if req.message.is_empty() || req.secret.is_empty() {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Missing required fields".into()),
        });
    }
    let secret_bytes = match req.secret.from_base58() {
        Ok(b) if b.len() == 64 => b,
        _ => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid secret".into()),
            });
        }
    };
    let keypair = match DalekKeypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid secret bytes".into()),
            });
        }
    };

    let sig = keypair.sign(req.message.as_bytes());
    let data = SignMessageResponse {
        signature: base64::encode(sig.to_bytes()),
        public_key: keypair.public.to_bytes().to_base58(),
        message: req.message.clone(),
    };
    HttpResponse::Ok().json(Response {
        success: true,
        data: Some(data),
        error: None,
    })
}

async fn verify_message(req: web::Json<VerifyMessageRequest>) -> HttpResponse {
    if req.message.is_empty() || req.signature.is_empty() || req.pubkey.is_empty() {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Missing required fields".into()),
        });
    }
    let pubkey_bytes = match req.pubkey.from_base58() {
        Ok(b) => b,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid pubkey format".into()),
            });
        }
    };
    let public_key = match DalekPubkey::from_bytes(&pubkey_bytes) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid pubkey bytes".into()),
            });
        }
    };
    let sig_bytes = match base64::decode(&req.signature) {
        Ok(b) => b,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid signature base64".into()),
            });
        }
    };
    let signature = match DalekSignature::from_bytes(&sig_bytes) {
        Ok(s) => s,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid signature bytes".into()),
            });
        }
    };

    let valid = public_key
        .verify(req.message.as_bytes(), &signature)
        .is_ok();
    let data = VerifyMessageResponse {
        valid,
        message: req.message.clone(),
        pubkey: req.pubkey.clone(),
    };
    HttpResponse::Ok().json(Response {
        success: true,
        data: Some(data),
        error: None,
    })
}

async fn send_sol(req: web::Json<SendSolRequest>) -> HttpResponse {
    if req.recent_blockhash.is_empty()
        || req.secret.is_empty()
        || req.to.is_empty()
        || req.lamports == 0
    {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Missing fields or zero lamports".into()),
        });
    }

    // Decode and parse fee-payer keypair
    let secret_bytes = match req.secret.from_base58() {
        Ok(b) if b.len() == 64 => b,
        _ => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid secret".into()),
            });
        }
    };
    let payer = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid keypair bytes".into()),
            });
        }
    };
    let from_pubkey = payer.pubkey();

    // Decode recipient
    let to_pubkey = match Pubkey::from_str(&req.to) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid recipient pubkey".into()),
            });
        }
    };

    // Decode blockhash
    let recent_blockhash = match Hash::from_str(&req.recent_blockhash) {
        Ok(h) => h,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid blockhash".into()),
            });
        }
    };

    // Build and sign transaction
    let ix = system_instruction::transfer(&from_pubkey, &to_pubkey, req.lamports);
    let message = Message::new(&[ix], Some(&from_pubkey));
    let tx = Transaction::new(&[&payer], message, recent_blockhash);

    // Serialize via bincode, then base64-encode
    let serialized = bincode::serialize(&tx).unwrap();
    let encoded = base64::encode(&serialized);

    HttpResponse::Ok().json(Response {
        success: true,
        data: Some(TxPayload {
            transaction: encoded,
        }),
        error: None,
    })
}

async fn send_token(req: web::Json<SendTokenRequest>) -> HttpResponse {
    if req.recent_blockhash.is_empty()
        || req.secret.is_empty()
        || req.owner.is_empty()
        || req.mint.is_empty()
        || req.destination.is_empty()
        || req.amount == 0
    {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Missing fields or zero amount".into()),
        });
    }

    // Parse owner pubkey + keypair
    let owner_pubkey = match Pubkey::from_str(&req.owner) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid owner pubkey".into()),
            });
        }
    };
    let secret_bytes = match req.secret.from_base58() {
        Ok(b) if b.len() == 64 => b,
        _ => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid secret".into()),
            });
        }
    };
    let owner_kp = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) if kp.pubkey() == owner_pubkey => kp,
        _ => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Secret does not match owner".into()),
            });
        }
    };

    // Parse mint & destination
    let mint_pubkey = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid mint pubkey".into()),
            });
        }
    };
    let dest_owner = match Pubkey::from_str(&req.destination) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid destination pubkey".into()),
            });
        }
    };

    // Decode blockhash
    let recent_blockhash = match Hash::from_str(&req.recent_blockhash) {
        Ok(h) => h,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid blockhash".into()),
            });
        }
    };

    // Compute ATAs
    let source_ata = get_associated_token_address(&owner_pubkey, &mint_pubkey);
    let dest_ata = get_associated_token_address(&dest_owner, &mint_pubkey);

    // Build instruction
    let ix = match instruction::transfer(
        &spl_token::id(),
        &source_ata,
        &dest_ata,
        &owner_pubkey,
        &[],
        req.amount,
    ) {
        Ok(ix) => ix,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Failed to build token transfer".into()),
            });
        }
    };

    // Build + sign tx
    let message = Message::new(&[ix], Some(&owner_pubkey));
    let tx = Transaction::new(&[&owner_kp], message, recent_blockhash);

    // Serialize + encode
    let serialized = bincode::serialize(&tx).unwrap();
    let encoded = base64::encode(&serialized);

    HttpResponse::Ok().json(Response {
        success: true,
        data: Some(TxPayload {
            transaction: encoded,
        }),
        error: None,
    })
}
