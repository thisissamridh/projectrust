use actix_web::{App, HttpResponse, HttpServer, web};
use base58::{FromBase58, ToBase58};
use base64::{self, Engine as _, engine::general_purpose};
use borsh::{BorshDeserialize, BorshSerialize}; // <-- Import borsh
use serde::{Deserialize, Serialize};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Signature, Signer},
    signer::keypair::Keypair,
    system_instruction, system_program,
};
use spl_associated_token_account::get_associated_token_address;
use spl_token::id as spl_token_program_id;
use std::str::FromStr;

// --- borsh-compatible Instruction Structs for Serialization ---
// These structs define the exact data layout for SPL Token instructions.

#[derive(BorshSerialize, BorshDeserialize)]
struct MintToInstructionData {
    instruction: u8, // MintTo instruction is `7`
    amount: u64,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct TransferInstructionData {
    instruction: u8, // Transfer instruction is `3`
    amount: u64,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct InitializeMintInstructionData {
    instruction: u8, // InitializeMint instruction is `0`
    decimals: u8,
    mint_authority: Pubkey,
    freeze_authority_option: u8, // 0 for None
                                 // Freeze authority pubkey would go here if option was 1
}

// --- Generic Response Wrappers ---

#[derive(Serialize)]
struct Response<T: Serialize> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn create_error_response(msg: &str) -> HttpResponse {
    HttpResponse::Ok().json(Response::<()> {
        success: false,
        data: None,
        error: Some(msg.to_string()),
    })
}

// --- Endpoint-Specific Structs ---

#[derive(Serialize)]
struct KeypairData {
    pubkey: String,
    secret: String,
}
#[derive(Serialize)]
struct AccountMetaSnakeCase {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}
#[derive(Serialize)]
struct InstructionResponseSnakeCase {
    program_id: String,
    accounts: Vec<AccountMetaSnakeCase>,
    instruction_data: String,
}
#[derive(Serialize)]
struct AccountMetaCamelCase {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
}
#[derive(Serialize)]
struct SendTokenResponse {
    program_id: String,
    accounts: Vec<AccountMetaCamelCase>,
    instruction_data: String,
}
#[derive(Serialize)]
struct SendSolResponse {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}
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

    // Manually construct the instruction accounts as per SPL spec
    let accounts_vec = vec![
        AccountMeta::new(mint, false), // The mint account to initialize
        AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false), // Rent sysvar
    ];

    // Manually serialize the instruction data using borsh
    let instruction_data = InitializeMintInstructionData {
        instruction: 0,
        decimals: req.decimals,
        mint_authority,
        freeze_authority_option: 0,
    };
    let data_serialized = match instruction_data.try_to_vec() {
        Ok(data) => data,
        Err(e) => return create_error_response(&format!("Failed to serialize instruction: {}", e)),
    };

    let accounts_response = accounts_vec
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
            program_id: spl_token_program_id().to_string(),
            accounts: accounts_response,
            instruction_data: general_purpose::STANDARD.encode(&data_serialized),
        }),
        error: None,
    })
}

async fn mint_token(req: web::Json<TokenMintRequest>) -> HttpResponse {
    let mint_pubkey = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => return create_error_response("Invalid mint public key"),
    };
    let destination_token_account_pubkey = match Pubkey::from_str(&req.destination) {
        Ok(pk) => pk,
        Err(_) => return create_error_response("Invalid destination public key"),
    };
    let authority_pubkey = match Pubkey::from_str(&req.authority) {
        Ok(pk) => pk,
        Err(_) => return create_error_response("Invalid authority public key"),
    };

    // Manually construct the instruction accounts
    let accounts_vec = vec![
        AccountMeta::new(mint_pubkey, false), // The mint
        AccountMeta::new(destination_token_account_pubkey, false), // The token account to mint to
        AccountMeta::new_readonly(authority_pubkey, true), // The mint authority
    ];

    // Manually serialize the instruction data using borsh
    let instruction_data = MintToInstructionData {
        instruction: 7, // Instruction for MintTo
        amount: req.amount,
    };
    let data_serialized = match instruction_data.try_to_vec() {
        Ok(data) => data,
        Err(e) => return create_error_response(&format!("Failed to serialize instruction: {}", e)),
    };

    let accounts_response = accounts_vec
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
            program_id: spl_token_program_id().to_string(),
            accounts: accounts_response,
            instruction_data: general_purpose::STANDARD.encode(&data_serialized),
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

    let source_ata = get_associated_token_address(&owner_pubkey, &mint_pubkey);
    let destination_ata = get_associated_token_address(&destination_owner_pubkey, &mint_pubkey);

    // Manually construct the instruction accounts
    let accounts_vec = vec![
        AccountMeta::new(source_ata, false),      // Source token account
        AccountMeta::new(destination_ata, false), // Destination token account
        AccountMeta::new_readonly(owner_pubkey, true), // Owner of the source account
    ];

    // Manually serialize the instruction data using borsh
    let instruction_data = TransferInstructionData {
        instruction: 3, // Instruction for Transfer
        amount: req.amount,
    };
    let data_serialized = match instruction_data.try_to_vec() {
        Ok(data) => data,
        Err(e) => return create_error_response(&format!("Failed to serialize instruction: {}", e)),
    };

    let accounts_response = accounts_vec
        .into_iter()
        .map(|acc| AccountMetaCamelCase {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
        })
        .collect();

    HttpResponse::Ok().json(Response {
        success: true,
        data: Some(SendTokenResponse {
            program_id: spl_token_program_id().to_string(),
            accounts: accounts_response,
            instruction_data: general_purpose::STANDARD.encode(&data_serialized),
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

    // The solana_sdk::system_instruction::transfer helper is reliable and standard
    let ix = system_instruction::transfer(&from_pubkey, &to_pubkey, req.lamports);

    let accounts: Vec<String> = ix
        .accounts
        .iter()
        .map(|acc| acc.pubkey.to_string())
        .collect();

    HttpResponse::Ok().json(Response {
        success: true,
        data: Some(SendSolResponse {
            program_id: system_program::id().to_string(),
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
