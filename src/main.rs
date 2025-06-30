use actix_web::{App, HttpResponse, HttpServer, web};
use base58::{FromBase58, ToBase58};
use base64::{self, Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Signature, Signer},
    signer::keypair::Keypair,
    system_instruction,
};
use spl_associated_token_account::get_associated_token_address;
use spl_token::instruction;
use std::str::FromStr;

// --- Response & Request Structs (Mostly Unchanged) ---

#[derive(Serialize)]
struct Response<T: Serialize> {
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
struct AccountMetaResponse {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct InstructionResponse {
    program_id: String,
    accounts: Vec<AccountMetaResponse>,
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
    accounts: Vec<String>, // Spec requires a simple array of strings for this endpoint
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
struct SendTokenAccountResponse {
    pubkey: String,
    #[serde(rename = "isSigner")] // Spec requires camelCase for this endpoint
    is_signer: bool,
}

#[derive(Serialize)]
struct SendTokenResponse {
    program_id: String,
    accounts: Vec<SendTokenAccountResponse>,
    instruction_data: String,
}

// --- Helper for creating error responses ---
fn create_error_response(msg: &str) -> HttpResponse {
    // FIX: All error responses now use HttpResponse::Ok() and a JSON body
    // with "success": false, as per the specification.
    HttpResponse::Ok().json(Response::<()> {
        success: false,
        data: None,
        error: Some(msg.to_string()),
    })
}

// --- API Handlers ---

async fn generate_keypair() -> HttpResponse {
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

async fn create_token(req: web::Json<TokenCreateRequest>) -> HttpResponse {
    if req.mint_authority.is_empty() || req.mint.is_empty() {
        return create_error_response("Missing required fields");
    }

    let mint_authority = match Pubkey::from_str(&req.mint_authority) {
        Ok(pk) => pk,
        Err(_) => return create_error_response("Invalid mintAuthority public key"),
    };

    let mint = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => return create_error_response("Invalid mint public key"),
    };

    let ix = match instruction::initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        None, // No freeze authority
        req.decimals,
    ) {
        Ok(ix) => ix,
        Err(e) => return create_error_response(&format!("Failed to create instruction: {}", e)),
    };

    let accounts = ix
        .accounts
        .into_iter()
        .map(|acc| AccountMetaResponse {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    let data = InstructionResponse {
        program_id: ix.program_id.to_string(),
        accounts,
        instruction_data: general_purpose::STANDARD.encode(&ix.data),
    };

    HttpResponse::Ok().json(Response {
        success: true,
        data: Some(data),
        error: None,
    })
}

async fn mint_token(req: web::Json<TokenMintRequest>) -> HttpResponse {
    if req.mint.is_empty() || req.destination.is_empty() || req.authority.is_empty() {
        return create_error_response("Missing required fields");
    }

    let mint_pubkey = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => return create_error_response("Invalid mint public key"),
    };
    let destination_pubkey = match Pubkey::from_str(&req.destination) {
        Ok(pk) => pk,
        Err(_) => return create_error_response("Invalid destination public key"),
    };
    let authority_pubkey = match Pubkey::from_str(&req.authority) {
        Ok(pk) => pk,
        Err(_) => return create_error_response("Invalid authority public key"),
    };

    let ix = match instruction::mint_to(
        &spl_token::id(),
        &mint_pubkey,
        &destination_pubkey,
        &authority_pubkey,
        &[], // No multisig
        req.amount,
    ) {
        Ok(ix) => ix,
        Err(e) => return create_error_response(&format!("Failed to create instruction: {}", e)),
    };

    let accounts = ix
        .accounts
        .into_iter()
        .map(|acc| AccountMetaResponse {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    let data = InstructionResponse {
        program_id: ix.program_id.to_string(),
        accounts,
        instruction_data: general_purpose::STANDARD.encode(&ix.data),
    };
    HttpResponse::Ok().json(Response {
        success: true,
        data: Some(data),
        error: None,
    })
}

async fn sign_message(req: web::Json<SignMessageRequest>) -> HttpResponse {
    if req.message.is_empty() || req.secret.is_empty() {
        return create_error_response("Missing required fields");
    }

    let secret_bytes = match req.secret.from_base58() {
        Ok(bytes) => bytes,
        Err(_) => return create_error_response("Invalid secret key format"),
    };

    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => return create_error_response("Invalid secret key"),
    };

    let signature = keypair.sign_message(req.message.as_bytes());

    let data = SignMessageResponse {
        signature: general_purpose::STANDARD.encode(signature.as_ref()),
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
    if req.message.is_empty() || req.signature.is_empty() || req.pubkey.is_empty() {
        return create_error_response("Missing required fields");
    }

    let pubkey = match Pubkey::from_str(&req.pubkey) {
        Ok(pk) => pk,
        Err(_) => return create_error_response("Invalid public key"),
    };

    let signature_bytes = match general_purpose::STANDARD.decode(&req.signature) {
        Ok(bytes) => bytes,
        Err(_) => return create_error_response("Invalid signature format"),
    };

    let signature = match Signature::try_from(signature_bytes) {
        Ok(sig) => sig,
        Err(_) => return create_error_response("Invalid signature"),
    };

    let valid = signature.verify(pubkey.as_ref(), req.message.as_bytes());

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
    if req.from.is_empty() || req.to.is_empty() {
        return create_error_response("Missing required fields");
    }
    if req.lamports == 0 {
        return create_error_response("Lamports must be greater than 0");
    }

    let from_pubkey = match Pubkey::from_str(&req.from) {
        Ok(pk) => pk,
        Err(_) => return create_error_response("Invalid from public key"),
    };
    let to_pubkey = match Pubkey::from_str(&req.to) {
        Ok(pk) => pk,
        Err(_) => return create_error_response("Invalid to public key"),
    };

    if from_pubkey == to_pubkey {
        return create_error_response("From and to addresses cannot be the same");
    }

    let ix = system_instruction::transfer(&from_pubkey, &to_pubkey, req.lamports);

    let accounts = ix
        .accounts
        .iter()
        .map(|acc| acc.pubkey.to_string())
        .collect();

    let data = SendSolResponse {
        program_id: ix.program_id.to_string(),
        accounts,
        instruction_data: general_purpose::STANDARD.encode(&ix.data),
    };

    HttpResponse::Ok().json(Response {
        success: true,
        data: Some(data),
        error: None,
    })
}

async fn send_token(req: web::Json<SendTokenRequest>) -> HttpResponse {
    if req.destination.is_empty() || req.mint.is_empty() || req.owner.is_empty() {
        return create_error_response("Missing required fields");
    }
    if req.amount == 0 {
        return create_error_response("Amount must be greater than 0");
    }

    let owner_pubkey = match Pubkey::from_str(&req.owner) {
        Ok(pk) => pk,
        Err(_) => return create_error_response("Invalid owner public key"),
    };
    let mint_pubkey = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => return create_error_response("Invalid mint public key"),
    };
    // The destination in the request is the *wallet address* of the recipient, not their token account
    let destination_owner_pubkey = match Pubkey::from_str(&req.destination) {
        Ok(pk) => pk,
        Err(_) => return create_error_response("Invalid destination public key"),
    };

    if owner_pubkey == destination_owner_pubkey {
        return create_error_response("Owner and destination addresses cannot be the same");
    }

    // A standard token transfer goes between Associated Token Accounts (ATAs)
    let source_ata = get_associated_token_address(&owner_pubkey, &mint_pubkey);
    let destination_ata = get_associated_token_address(&destination_owner_pubkey, &mint_pubkey);

    let ix = match instruction::transfer(
        &spl_token::id(),
        &source_ata,
        &destination_ata,
        &owner_pubkey,
        &[],
        req.amount,
    ) {
        Ok(ix) => ix,
        Err(e) => return create_error_response(&format!("Failed to create instruction: {}", e)),
    };

    // The spec for this endpoint requires a specific account format
    let accounts = ix
        .accounts
        .into_iter()
        .map(|acc| SendTokenAccountResponse {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
        })
        .collect();

    let data = SendTokenResponse {
        program_id: ix.program_id.to_string(),
        accounts,
        instruction_data: general_purpose::STANDARD.encode(&ix.data),
    };

    HttpResponse::Ok().json(Response {
        success: true,
        data: Some(data),
        error: None,
    })
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Starting Solana Fellowship Server on http://0.0.0.0:8080");
    HttpServer::new(|| {
        App::new()
            .route("/keypair", web::post().to(generate_keypair))
            .route("/token/create", web::post().to(create_token))
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
