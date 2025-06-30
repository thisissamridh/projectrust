use actix_web::{App, HttpResponse, HttpServer, web};
use base58::{FromBase58, ToBase58};
use base64;
use serde::{Deserialize, Serialize};
use solana_sdk::{
    pubkey::Pubkey,
    signer::{Signer, keypair::Keypair},
    system_instruction,
};
use spl_associated_token_account::get_associated_token_address;
use spl_token::instruction;
use std::str::FromStr;

use ed25519_dalek::{
    Keypair as DalekKeypair, PublicKey as DalekPubkey, Signature as DalekSignature, Signer as _,
    Verifier as _,
};

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
    // Validation
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
            error: Some("Decimals must be between 0 and 9".into()),
        });
    }

    // Parse pubkeys
    let mint_auth = match Pubkey::from_str(&req.mint_authority) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid mint authority".into()),
            });
        }
    };
    let mint_addr = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid mint address".into()),
            });
        }
    };

    // Build instruction
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
                error: Some("Failed to create instruction".into()),
            });
        }
    };

    // Return
    let accounts = ix
        .accounts
        .iter()
        .map(|acc| Account {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();
    let data = InstructionResponse {
        program_id: ix.program_id.to_string(),
        accounts,
        instruction_data: base64::encode(&ix.data),
    };
    HttpResponse::Ok().json(Response {
        success: true,
        data: Some(data),
        error: None,
    })
}

async fn mint_token(req: web::Json<TokenMintRequest>) -> HttpResponse {
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
            error: Some("Amount must be greater than 0".into()),
        });
    }

    let mint_addr = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid mint address".into()),
            });
        }
    };
    let dest_addr = match Pubkey::from_str(&req.destination) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid destination address".into()),
            });
        }
    };
    let auth_addr = match Pubkey::from_str(&req.authority) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid authority address".into()),
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
                error: Some("Failed to create instruction".into()),
            });
        }
    };

    let accounts = ix
        .accounts
        .iter()
        .map(|acc| Account {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();
    let data = InstructionResponse {
        program_id: ix.program_id.to_string(),
        accounts,
        instruction_data: base64::encode(&ix.data),
    };
    HttpResponse::Ok().json(Response {
        success: true,
        data: Some(data),
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
                error: Some("Invalid secret key".into()),
            });
        }
    };

    let keypair = match DalekKeypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid secret key bytes".into()),
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
                error: Some("Invalid public key format".into()),
            });
        }
    };
    let public_key = match DalekPubkey::from_bytes(&pubkey_bytes) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid public key bytes".into()),
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
    if req.from.is_empty() || req.to.is_empty() || req.lamports == 0 {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Missing required fields or zero lamports".into()),
        });
    }

    let from = match Pubkey::from_str(&req.from) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid from address".into()),
            });
        }
    };
    let to = match Pubkey::from_str(&req.to) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid to address".into()),
            });
        }
    };
    if from == to {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Cannot transfer to same address".into()),
        });
    }

    let ix = system_instruction::transfer(&from, &to, req.lamports);
    let accounts = ix
        .accounts
        .iter()
        .map(|acc| acc.pubkey.to_string())
        .collect();
    let data = SendSolResponse {
        program_id: ix.program_id.to_string(),
        accounts,
        instruction_data: base64::encode(&ix.data),
    };
    HttpResponse::Ok().json(Response {
        success: true,
        data: Some(data),
        error: None,
    })
}

async fn send_token(req: web::Json<SendTokenRequest>) -> HttpResponse {
    if req.destination.is_empty() || req.mint.is_empty() || req.owner.is_empty() || req.amount == 0
    {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Missing required fields or zero amount".into()),
        });
    }

    let dest = match Pubkey::from_str(&req.destination) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid destination address".into()),
            });
        }
    };
    let mint = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid mint address".into()),
            });
        }
    };
    let owner = match Pubkey::from_str(&req.owner) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid owner address".into()),
            });
        }
    };
    if owner == dest {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Cannot transfer to same address".into()),
        });
    }

    let source_ata = get_associated_token_address(&owner, &mint);
    let dest_ata = get_associated_token_address(&dest, &mint);

    let ix = match instruction::transfer(
        &spl_token::id(),
        &source_ata,
        &dest_ata,
        &owner,
        &[],
        req.amount,
    ) {
        Ok(ix) => ix,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Failed to create instruction".into()),
            });
        }
    };

    let accounts = ix
        .accounts
        .iter()
        .map(|acc| TokenAccount {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
        })
        .collect();
    let data = SendTokenResponse {
        program_id: ix.program_id.to_string(),
        accounts,
        instruction_data: base64::encode(&ix.data),
    };
    HttpResponse::Ok().json(Response {
        success: true,
        data: Some(data),
        error: None,
    })
}
