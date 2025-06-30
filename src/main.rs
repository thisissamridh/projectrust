use actix_web::{App, HttpResponse, HttpServer, middleware::Logger, web};
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

// Generic response wrapper
#[derive(Serialize)]
struct Response<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl<T> Response<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    fn error(message: String) -> Response<()> {
        Response {
            success: false,
            data: None,
            error: Some(message),
        }
    }
}

// Keypair endpoint structures
#[derive(Serialize)]
struct KeypairData {
    pubkey: String,
    secret: String,
}

// Token create endpoint structures
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

// Token mint endpoint structures
#[derive(Deserialize)]
struct TokenMintRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

// Message sign endpoint structures
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

// Message verify endpoint structures
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

// Send SOL endpoint structures
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

// Send token endpoint structures
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
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    println!("🚀 Starting Solana API server on http://0.0.0.0:8080");
    println!("📋 Available endpoints:");
    println!("  GET  /health           - Health check");
    println!("  POST /keypair          - Generate new keypair");
    println!("  POST /token/create     - Create SPL token mint instruction");
    println!("  POST /token/mint       - Create mint tokens instruction");
    println!("  POST /message/sign     - Sign message with private key");
    println!("  POST /message/verify   - Verify message signature");
    println!("  POST /send/sol         - Create SOL transfer instruction");
    println!("  POST /send/token       - Create SPL token transfer instruction");

    HttpServer::new(|| {
        App::new()
            .wrap(Logger::default())
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

/// Health check endpoint
async fn health() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "service": "solana-api",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

/// Generate a new Solana keypair
async fn make_keypair() -> HttpResponse {
    let keypair = Keypair::new();
    let data = KeypairData {
        pubkey: keypair.pubkey().to_string(),
        secret: keypair.to_bytes().to_base58(),
    };

    HttpResponse::Ok().json(Response::success(data))
}

/// Create SPL token mint initialization instruction
async fn make_token(req: web::Json<TokenCreateRequest>) -> HttpResponse {
    // Validate required fields
    if req.mint_authority.trim().is_empty() || req.mint.trim().is_empty() {
        return HttpResponse::BadRequest().json(Response::<()>::error(
            "Missing required fields: mintAuthority and mint are required".to_string(),
        ));
    }

    // Validate decimals (SPL Token standard allows 0-9 decimals)
    if req.decimals > 9 {
        return HttpResponse::BadRequest().json(Response::<()>::error(
            "Decimals must be between 0 and 9".to_string(),
        ));
    }

    // Parse mint authority public key
    let mint_authority = match Pubkey::from_str(&req.mint_authority) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()>::error(
                "Invalid mint authority public key".to_string(),
            ));
        }
    };

    // Parse mint address
    let mint_address = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest()
                .json(Response::<()>::error("Invalid mint address".to_string()));
        }
    };

    // Create initialize mint instruction
    let instruction = match instruction::initialize_mint(
        &spl_token::id(),
        &mint_address,
        &mint_authority,
        None, // No freeze authority
        req.decimals,
    ) {
        Ok(ix) => ix,
        Err(e) => {
            return HttpResponse::InternalServerError().json(Response::<()>::error(format!(
                "Failed to create instruction: {}",
                e
            )));
        }
    };

    let accounts: Vec<Account> = instruction
        .accounts
        .iter()
        .map(|acc| Account {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    let data = InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::encode(&instruction.data),
    };

    HttpResponse::Ok().json(Response::success(data))
}

/// Create mint tokens instruction
async fn mint_token(req: web::Json<TokenMintRequest>) -> HttpResponse {
    // Validate required fields
    if req.mint.trim().is_empty()
        || req.destination.trim().is_empty()
        || req.authority.trim().is_empty()
    {
        return HttpResponse::BadRequest().json(Response::<()>::error(
            "Missing required fields: mint, destination, and authority are required".to_string(),
        ));
    }

    // Validate amount
    if req.amount == 0 {
        return HttpResponse::BadRequest().json(Response::<()>::error(
            "Amount must be greater than 0".to_string(),
        ));
    }

    // Parse addresses
    let mint_address = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest()
                .json(Response::<()>::error("Invalid mint address".to_string()));
        }
    };

    let destination_address = match Pubkey::from_str(&req.destination) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()>::error(
                "Invalid destination address".to_string(),
            ));
        }
    };

    let authority_address = match Pubkey::from_str(&req.authority) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()>::error(
                "Invalid authority address".to_string(),
            ));
        }
    };

    // Create mint to instruction
    let instruction = match instruction::mint_to(
        &spl_token::id(),
        &mint_address,
        &destination_address,
        &authority_address,
        &[], // No additional signers
        req.amount,
    ) {
        Ok(ix) => ix,
        Err(e) => {
            return HttpResponse::InternalServerError().json(Response::<()>::error(format!(
                "Failed to create instruction: {}",
                e
            )));
        }
    };

    let accounts: Vec<Account> = instruction
        .accounts
        .iter()
        .map(|acc| Account {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    let data = InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::encode(&instruction.data),
    };

    HttpResponse::Ok().json(Response::success(data))
}

/// Sign a message with a private key
async fn sign_message(req: web::Json<SignMessageRequest>) -> HttpResponse {
    // Validate required fields
    if req.message.is_empty() {
        return HttpResponse::BadRequest()
            .json(Response::<()>::error("Message cannot be empty".to_string()));
    }

    if req.secret.trim().is_empty() {
        return HttpResponse::BadRequest()
            .json(Response::<()>::error("Secret key is required".to_string()));
    }

    // Decode secret key from base58
    let secret_bytes = match req.secret.from_base58() {
        Ok(bytes) => bytes,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()>::error(
                "Invalid secret key format (must be base58)".to_string(),
            ));
        }
    };

    // Validate secret key length
    if secret_bytes.len() != 64 {
        return HttpResponse::BadRequest().json(Response::<()>::error(
            "Invalid secret key length (must be 64 bytes)".to_string(),
        ));
    }

    // Create keypair from secret bytes
    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => {
            return HttpResponse::BadRequest()
                .json(Response::<()>::error("Invalid secret key".to_string()));
        }
    };

    // Sign the message
    let signature = keypair.sign_message(req.message.as_bytes());
    let signature_base64 = base64::encode(signature.as_ref());

    let data = SignMessageResponse {
        signature: signature_base64,
        public_key: keypair.pubkey().to_string(),
        message: req.message.clone(),
    };

    HttpResponse::Ok().json(Response::success(data))
}

/// Verify a message signature
async fn verify_message(req: web::Json<VerifyMessageRequest>) -> HttpResponse {
    // Validate required fields
    if req.message.is_empty() || req.signature.trim().is_empty() || req.pubkey.trim().is_empty() {
        return HttpResponse::BadRequest().json(Response::<()>::error(
            "Missing required fields: message, signature, and pubkey are required".to_string(),
        ));
    }

    // Parse public key
    let public_key = match Pubkey::from_str(&req.pubkey) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest()
                .json(Response::<()>::error("Invalid public key".to_string()));
        }
    };

    // Decode base64 signature
    let signature_bytes = match base64::decode(&req.signature) {
        Ok(bytes) => bytes,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()>::error(
                "Invalid signature format (must be base64)".to_string(),
            ));
        }
    };

    // Validate signature length
    if signature_bytes.len() != 64 {
        return HttpResponse::BadRequest().json(Response::<()>::error(
            "Invalid signature length (must be 64 bytes)".to_string(),
        ));
    }

    // Create signature from bytes
    let signature = match Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => {
            return HttpResponse::BadRequest()
                .json(Response::<()>::error("Invalid signature".to_string()));
        }
    };

    // Verify the signature
    let valid = signature.verify(public_key.as_ref(), req.message.as_bytes());

    let data = VerifyMessageResponse {
        valid,
        message: req.message.clone(),
        pubkey: req.pubkey.clone(),
    };

    HttpResponse::Ok().json(Response::success(data))
}

/// Create SOL transfer instruction
async fn send_sol(req: web::Json<SendSolRequest>) -> HttpResponse {
    // Validate required fields
    if req.from.trim().is_empty() || req.to.trim().is_empty() {
        return HttpResponse::BadRequest().json(Response::<()>::error(
            "Missing required fields: from and to addresses are required".to_string(),
        ));
    }

    // Validate amount
    if req.lamports == 0 {
        return HttpResponse::BadRequest().json(Response::<()>::error(
            "Amount must be greater than 0".to_string(),
        ));
    }

    // Parse addresses
    let from_address = match Pubkey::from_str(&req.from) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest()
                .json(Response::<()>::error("Invalid from address".to_string()));
        }
    };

    let to_address = match Pubkey::from_str(&req.to) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest()
                .json(Response::<()>::error("Invalid to address".to_string()));
        }
    };

    // Prevent self-transfer
    if from_address == to_address {
        return HttpResponse::BadRequest().json(Response::<()>::error(
            "Cannot transfer to the same address".to_string(),
        ));
    }

    // Create transfer instruction
    let instruction = system_instruction::transfer(&from_address, &to_address, req.lamports);

    // Extract account addresses as strings
    let accounts: Vec<String> = instruction
        .accounts
        .iter()
        .map(|acc| acc.pubkey.to_string())
        .collect();

    let data = SendSolResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::encode(&instruction.data),
    };

    HttpResponse::Ok().json(Response::success(data))
}

/// Create SPL token transfer instruction
async fn send_token(req: web::Json<SendTokenRequest>) -> HttpResponse {
    // Validate required fields
    if req.destination.trim().is_empty()
        || req.mint.trim().is_empty()
        || req.owner.trim().is_empty()
    {
        return HttpResponse::BadRequest().json(Response::<()>::error(
            "Missing required fields: destination, mint, and owner are required".to_string(),
        ));
    }

    // Validate amount
    if req.amount == 0 {
        return HttpResponse::BadRequest().json(Response::<()>::error(
            "Amount must be greater than 0".to_string(),
        ));
    }

    // Parse addresses
    let destination_address = match Pubkey::from_str(&req.destination) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()>::error(
                "Invalid destination address".to_string(),
            ));
        }
    };

    let mint_address = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest()
                .json(Response::<()>::error("Invalid mint address".to_string()));
        }
    };

    let owner_address = match Pubkey::from_str(&req.owner) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest()
                .json(Response::<()>::error("Invalid owner address".to_string()));
        }
    };

    // Prevent self-transfer
    if owner_address == destination_address {
        return HttpResponse::BadRequest().json(Response::<()>::error(
            "Cannot transfer to the same address".to_string(),
        ));
    }

    // Get associated token accounts
    let source_ata = get_associated_token_address(&owner_address, &mint_address);
    let destination_ata = get_associated_token_address(&destination_address, &mint_address);

    // Create transfer instruction
    let instruction = match instruction::transfer(
        &spl_token::id(),
        &source_ata,
        &destination_ata,
        &owner_address,
        &[], // No additional signers
        req.amount,
    ) {
        Ok(ix) => ix,
        Err(e) => {
            return HttpResponse::InternalServerError().json(Response::<()>::error(format!(
                "Failed to create instruction: {}",
                e
            )));
        }
    };

    // Map accounts with signer information
    let accounts: Vec<TokenAccount> = instruction
        .accounts
        .iter()
        .map(|acc| TokenAccount {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
        })
        .collect();

    let data = SendTokenResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: base64::encode(&instruction.data),
    };

    HttpResponse::Ok().json(Response::success(data))
}
