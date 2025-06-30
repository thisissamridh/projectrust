use actix_web::{App, HttpResponse, HttpServer, web};
use base58::{FromBase58, ToBase58};
use base64::{self, Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    instruction::AccountMeta,
    pubkey::Pubkey,
    signature::{Signature, Signer},
    signer::keypair::Keypair,
    system_instruction, system_program,
};
use spl_associated_token_account::get_associated_token_address;
use spl_token::{id as spl_token_program_id, instruction};
use std::str::FromStr;

// --- Generic Response Wrappers ---

#[derive(Serialize)]
struct Response<T: Serialize> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

// Helper to create the standard error response with HTTP 200 status
fn create_error_response(msg: &str) -> HttpResponse {
    HttpResponse::Ok().json(Response::<()> {
        success: false,
        data: None,
        error: Some(msg.to_string()),
    })
}

// --- Endpoint-Specific Structs (Keypair) ---
#[derive(Serialize)]
struct KeypairData {
    pubkey: String,
    secret: String,
}

// --- Endpoint-Specific Structs (Instructions) ---

// Struct for endpoints requiring snake_case account fields (`/token/create`, `/token/mint`)
#[derive(Serialize)]
struct AccountMetaSnakeCase {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

// Struct for the generic instruction response using snake_case accounts
#[derive(Serialize)]
struct InstructionResponseSnakeCase {
    program_id: String,
    accounts: Vec<AccountMetaSnakeCase>,
    instruction_data: String,
}

// Struct for endpoints requiring camelCase account fields (`/send/token`)
#[derive(Serialize)]
struct AccountMetaCamelCase {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
}

// Struct for the `/send/token` response
#[derive(Serialize)]
struct SendTokenResponse {
    program_id: String,
    accounts: Vec<AccountMetaCamelCase>,
    instruction_data: String,
}

// Struct for the `/send/sol` response (unique format)
#[derive(Serialize)]
struct SendSolResponse {
    program_id: String,
    accounts: Vec<String>, // Spec requires a simple array of strings
    instruction_data: String,
}

// --- Endpoint-Specific Structs (Requests) ---

#[derive(Deserialize)]
struct TokenCreateRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
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

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

// --- API Handlers ---

async fn generate_keypair() -> HttpResponse {
    let kp = Keypair::new();
    HttpResponse::Ok().json(Response {
        success: true,
        data: Some(KeypairData {
            pubkey: kp.pubkey().to_string(),
            secret: kp.to_bytes().to_base58(),
        }),
        error: None,
    })
}

async fn create_token(req: web::Json<TokenCreateRequest>) -> HttpResponse {
    let mint_authority = match Pubkey::from_str(&req.mint_authority) {
        Ok(pk) => pk,
        Err(_) => return create_error_response("Invalid mintAuthority public key"),
    };
    let mint = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => return create_error_response("Invalid mint public key"),
    };

    let ix = match instruction::initialize_mint(
        &spl_token_program_id(),
        &mint,
        &mint_authority,
        None,
        req.decimals,
    ) {
        Ok(ix) => ix,
        Err(e) => return create_error_response(&format!("Failed to create instruction: {}", e)),
    };

    let accounts = ix
        .accounts
        .into_iter()
        .map(|acc| AccountMetaSnakeCase {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    HttpResponse::Ok().json(Response {
        success: true,
        data: Some(InstructionResponseSnakeCase {
            program_id: ix.program_id.to_string(),
            accounts,
            instruction_data: general_purpose::STANDARD.encode(&ix.data),
        }),
        error: None,
    })
}

async fn mint_token(req: web::Json<TokenMintRequest>) -> HttpResponse {
    let mint_pubkey = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => return create_error_response("Invalid mint public key"),
    };
    // Per SPL spec, `destination` for `mint_to` is the token account, not the user's wallet.
    // The test request will provide the correct address.
    let destination_token_account_pubkey = match Pubkey::from_str(&req.destination) {
        Ok(pk) => pk,
        Err(_) => return create_error_response("Invalid destination public key"),
    };
    let authority_pubkey = match Pubkey::from_str(&req.authority) {
        Ok(pk) => pk,
        Err(_) => return create_error_response("Invalid authority public key"),
    };

    let ix = match instruction::mint_to(
        &spl_token_program_id(),
        &mint_pubkey,
        &destination_token_account_pubkey,
        &authority_pubkey,
        &[],
        req.amount,
    ) {
        Ok(ix) => ix,
        Err(e) => return create_error_response(&format!("Failed to create instruction: {}", e)),
    };

    let accounts = ix
        .accounts
        .into_iter()
        .map(|acc| AccountMetaSnakeCase {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    HttpResponse::Ok().json(Response {
        success: true,
        data: Some(InstructionResponseSnakeCase {
            program_id: ix.program_id.to_string(),
            accounts,
            instruction_data: general_purpose::STANDARD.encode(&ix.data),
        }),
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
    HttpResponse::Ok().json(Response {
        success: true,
        data: Some(SignMessageResponse {
            signature: general_purpose::STANDARD.encode(signature.as_ref()),
            public_key: keypair.pubkey().to_string(),
            message: req.message.clone(),
        }),
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
    let from_pubkey = match Pubkey::from_str(&req.from) {
        Ok(pk) => pk,
        Err(_) => return create_error_response("Invalid from public key"),
    };
    let to_pubkey = match Pubkey::from_str(&req.to) {
        Ok(pk) => pk,
        Err(_) => return create_error_response("Invalid to public key"),
    };
    let ix = system_instruction::transfer(&from_pubkey, &to_pubkey, req.lamports);

    // Spec requires a simple array of strings for this endpoint's accounts.
    let accounts: Vec<String> = ix
        .accounts
        .iter()
        .map(|acc| acc.pubkey.to_string())
        .collect();

    HttpResponse::Ok().json(Response {
        success: true,
        data: Some(SendSolResponse {
            program_id: system_program::id().to_string(), // Use the constant
            accounts,
            instruction_data: general_purpose::STANDARD.encode(&ix.data),
        }),
        error: None,
    })
}

async fn send_token(req: web::Json<SendTokenRequest>) -> HttpResponse {
    let owner_pubkey = match Pubkey::from_str(&req.owner) {
        Ok(pk) => pk,
        Err(_) => return create_error_response("Invalid owner public key"),
    };
    let mint_pubkey = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => return create_error_response("Invalid mint public key"),
    };
    let destination_owner_pubkey = match Pubkey::from_str(&req.destination) {
        Ok(pk) => pk,
        Err(_) => return create_error_response("Invalid destination public key"),
    };

    // This is the "RPC-like" logic: derive the ATAs from the wallet addresses.
    let source_ata = get_associated_token_address(&owner_pubkey, &mint_pubkey);
    let destination_ata = get_associated_token_address(&destination_owner_pubkey, &mint_pubkey);

    let ix = match instruction::transfer(
        &spl_token_program_id(),
        &source_ata,
        &destination_ata,
        &owner_pubkey,
        &[],
        req.amount,
    ) {
        Ok(ix) => ix,
        Err(e) => return create_error_response(&format!("Failed to create instruction: {}", e)),
    };

    // This endpoint requires camelCase "isSigner"
    let accounts = ix
        .accounts
        .into_iter()
        .map(|acc: AccountMeta| AccountMetaCamelCase {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
        })
        .collect();

    HttpResponse::Ok().json(Response {
        success: true,
        data: Some(SendTokenResponse {
            program_id: ix.program_id.to_string(),
            accounts,
            instruction_data: general_purpose::STANDARD.encode(&ix.data),
        }),
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
