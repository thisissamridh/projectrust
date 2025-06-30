use actix_web::{App, HttpResponse, HttpServer, web};
use base58::{FromBase58, ToBase58};
use base64;
use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
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

// Keypair endpoint
#[derive(Serialize)]
struct KeypairData {
    pubkey: String,
    secret: String,
}

// Token create endpoint
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

// Token mint endpoint
#[derive(Deserialize)]
struct TokenMintRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

// Message sign endpoint
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

// Message verify endpoint
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

// Send SOL endpoint
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

// Send token endpoint
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
    #[serde(rename = "isSigner")] // Changed to match spec exactly
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
    println!("Starting Solana server on port 8080");

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
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok"
    }))
}

async fn make_keypair() -> HttpResponse {
    let kp = Keypair::new();

    let data = KeypairData {
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
    // Check for missing/empty fields
    if req.mint_authority.is_empty() || req.mint.is_empty() {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Missing required fields".to_string()),
        });
    }

    // Validate decimals (SPL Token standard allows 0-9 decimals)
    if req.decimals > 9 {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Decimals must be between 0 and 9".to_string()),
        });
    }

    let mint_auth = match Pubkey::from_str(&req.mint_authority) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid mint authority".to_string()),
            });
        }
    };

    let mint_addr = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid mint address".to_string()),
            });
        }
    };

    // Create initialize mint instruction with proper error handling
    let ix = match instruction::initialize_mint(
        &spl_token::id(),
        &mint_addr,
        &mint_auth,
        None,
        req.decimals,
    ) {
        Ok(instruction) => instruction,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Failed to create instruction".to_string()),
            });
        }
    };

    let accounts: Vec<Account> = ix
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
    // Check for empty fields
    if req.mint.is_empty() || req.destination.is_empty() || req.authority.is_empty() {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Missing required fields".to_string()),
        });
    }

    // Validate amount
    if req.amount == 0 {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Amount must be greater than 0".to_string()),
        });
    }

    let mint_addr = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid mint address".to_string()),
            });
        }
    };

    let dest_addr = match Pubkey::from_str(&req.destination) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid destination address".to_string()),
            });
        }
    };

    let auth_addr = match Pubkey::from_str(&req.authority) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid authority address".to_string()),
            });
        }
    };

    // Create mint_to instruction with proper error handling
    let ix = match instruction::mint_to(
        &spl_token::id(),
        &mint_addr,
        &dest_addr,
        &auth_addr,
        &[],
        req.amount,
    ) {
        Ok(instruction) => instruction,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Failed to create instruction".to_string()),
            });
        }
    };

    let accounts: Vec<Account> = ix
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
    // Check for missing fields first
    if req.message.is_empty() {
        return HttpResponse::Ok().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Missing required fields".to_string()),
        });
    }

    if req.secret.is_empty() {
        return HttpResponse::Ok().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Missing required fields".to_string()),
        });
    }

    let secret_bytes = match req.secret.from_base58() {
        Ok(bytes) => bytes,
        Err(_) => {
            return HttpResponse::Ok().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid secret key format".to_string()),
            });
        }
    };

    if secret_bytes.len() != 64 {
        return HttpResponse::Ok().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Invalid secret key length".to_string()),
        });
    }

    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => {
            return HttpResponse::Ok().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid secret key".to_string()),
            });
        }
    };

    let signature = keypair.sign_message(req.message.as_bytes());

    // Convert signature to base64 as per spec
    let signature_bytes = signature.as_ref();
    let signature_base64 = base64::encode(signature_bytes);

    let data = SignMessageResponse {
        signature: signature_base64,
        public_key: keypair.pubkey().to_string(),
        message: req.message.clone(),
    };

    HttpResponse::Ok().json(Response {
        success: true,
        data: Some(data),
        error: None,
    })
}

async fn verify_message(req: web::Json<VerifyMessageRequest>) -> HttpResponse {
    // Check for missing fields
    if req.message.is_empty() || req.signature.is_empty() || req.pubkey.is_empty() {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Missing required fields".to_string()),
        });
    }

    let public_key = match Pubkey::from_str(&req.pubkey) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid public key".to_string()),
            });
        }
    };

    // Decode base64 signature as per spec
    let signature_bytes = match base64::decode(&req.signature) {
        Ok(bytes) => bytes,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid signature format".to_string()),
            });
        }
    };

    if signature_bytes.len() != 64 {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Invalid signature length".to_string()),
        });
    }

    let signature = match Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid signature".to_string()),
            });
        }
    };

    // Verify the signature against the message
    let valid = signature.verify(public_key.as_ref(), req.message.as_bytes());

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
    // Check for empty strings
    if req.from.is_empty() || req.to.is_empty() {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Missing required fields".to_string()),
        });
    }

    let from_addr = match Pubkey::from_str(&req.from) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid from address".to_string()),
            });
        }
    };

    let to_addr = match Pubkey::from_str(&req.to) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid to address".to_string()),
            });
        }
    };

    // Validate lamports amount
    if req.lamports == 0 {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Amount must be greater than 0".to_string()),
        });
    }

    // Prevent self-transfer which would be invalid
    if from_addr == to_addr {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Cannot transfer to same address".to_string()),
        });
    }

    // Create system transfer instruction
    let ix = system_instruction::transfer(&from_addr, &to_addr, req.lamports);

    // Spec wants accounts as array of strings for Send SOL
    let accounts: Vec<String> = ix
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
    // Check for missing/empty fields
    if req.destination.is_empty() || req.mint.is_empty() || req.owner.is_empty() {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Missing required fields".to_string()),
        });
    }

    // Validate amount
    if req.amount == 0 {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Amount must be greater than 0".to_string()),
        });
    }

    let dest_addr = match Pubkey::from_str(&req.destination) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid destination address".to_string()),
            });
        }
    };

    let mint_addr = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid mint address".to_string()),
            });
        }
    };

    let owner_addr = match Pubkey::from_str(&req.owner) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid owner address".to_string()),
            });
        }
    };

    // Prevent self-transfer
    if owner_addr == dest_addr {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Cannot transfer to same address".to_string()),
        });
    }

    let source_ata = get_associated_token_address(&owner_addr, &mint_addr);
    let dest_ata = get_associated_token_address(&dest_addr, &mint_addr);

    // Create transfer instruction with proper error handling
    let ix = match instruction::transfer(
        &spl_token::id(),
        &source_ata,
        &dest_ata,
        &owner_addr,
        &[],
        req.amount,
    ) {
        Ok(instruction) => instruction,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Failed to create instruction".to_string()),
            });
        }
    };

    // For send token - spec shows objects with pubkey and isSigner only (no isWritable)
    let accounts: Vec<TokenAccount> = ix
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
