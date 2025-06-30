use actix_web::{App, HttpResponse, HttpServer, web};
use base58::{FromBase58, ToBase58};
use base64;
use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signer;
use solana_sdk::signer::keypair::Keypair;
use solana_sdk::system_instruction;
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
                error: Some("Failed to create instruction".to_string()),
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

async fn mint_token(req: web::Json<TokenMintRequest>) -> HttpResponse {
    if req.mint.is_empty() || req.destination.is_empty() || req.authority.is_empty() {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Missing required fields".to_string()),
        });
    }

    if req.amount == 0 {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Amount must be greater than 0".to_string()),
        });
    }

    let mint_addr = Pubkey::from_str(&req.mint)
        .map_err(|_| {
            HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid mint address".to_string()),
            })
        })
        .unwrap();
    let dest_addr = Pubkey::from_str(&req.destination)
        .map_err(|_| {
            HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid destination address".to_string()),
            })
        })
        .unwrap();
    let auth_addr = Pubkey::from_str(&req.authority)
        .map_err(|_| {
            HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid authority address".to_string()),
            })
        })
        .unwrap();

    let ix = instruction::mint_to(
        &spl_token::id(),
        &mint_addr,
        &dest_addr,
        &auth_addr,
        &[],
        req.amount,
    )
    .map_err(|_| {
        HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Failed to create instruction".to_string()),
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
            error: Some("Missing required fields".to_string()),
        });
    }

    let secret_bytes = match req.secret.from_base58() {
        Ok(bytes) => bytes,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid secret key format".to_string()),
            });
        }
    };

    if secret_bytes.len() != 64 {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Invalid secret key length".to_string()),
        });
    }

    let keypair = DalekKeypair::from_bytes(&secret_bytes)
        .map_err(|_| {
            HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid secret key".to_string()),
            })
        })
        .unwrap();
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
            error: Some("Missing required fields".to_string()),
        });
    }

    let pubkey_bytes = match req.pubkey.from_base58() {
        Ok(bytes) => bytes,
        Err(_) => {
            return HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid public key format".to_string()),
            });
        }
    };

    let public_key = DalekPubkey::from_bytes(&pubkey_bytes)
        .map_err(|_| {
            HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid public key".to_string()),
            })
        })
        .unwrap();

    let sig_bytes = base64::decode(&req.signature)
        .map_err(|_| {
            HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid signature format".to_string()),
            })
        })
        .unwrap();
    let sig = DalekSignature::from_bytes(&sig_bytes)
        .map_err(|_| {
            HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid signature bytes".to_string()),
            })
        })
        .unwrap();

    let valid = public_key.verify(req.message.as_bytes(), &sig).is_ok();

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
    if req.from.is_empty() || req.to.is_empty() || req.lamports == 0 {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Missing required fields or zero lamports".to_string()),
        });
    }

    let from = Pubkey::from_str(&req.from)
        .map_err(|_| {
            HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid from address".to_string()),
            })
        })
        .unwrap();
    let to = Pubkey::from_str(&req.to)
        .map_err(|_| {
            HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid to address".to_string()),
            })
        })
        .unwrap();

    if from == to {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Cannot transfer to same address".to_string()),
        });
    }

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
    if req.destination.is_empty() || req.mint.is_empty() || req.owner.is_empty() || req.amount == 0
    {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Missing required fields or zero amount".to_string()),
        });
    }

    let dest = Pubkey::from_str(&req.destination)
        .map_err(|_| {
            HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid destination address".to_string()),
            })
        })
        .unwrap();
    let mint = Pubkey::from_str(&req.mint)
        .map_err(|_| {
            HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid mint address".to_string()),
            })
        })
        .unwrap();
    let owner = Pubkey::from_str(&req.owner)
        .map_err(|_| {
            HttpResponse::BadRequest().json(Response::<()> {
                success: false,
                data: None,
                error: Some("Invalid owner address".to_string()),
            })
        })
        .unwrap();

    if owner == dest {
        return HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Cannot transfer to same address".to_string()),
        });
    }

    let source_ata = get_associated_token_address(&owner, &mint);
    let dest_ata = get_associated_token_address(&dest, &mint);

    let ix = instruction::transfer(
        &spl_token::id(),
        &source_ata,
        &dest_ata,
        &owner,
        &[],
        req.amount,
    )
    .map_err(|_| {
        HttpResponse::BadRequest().json(Response::<()> {
            success: false,
            data: None,
            error: Some("Failed to create instruction".to_string()),
        })
    })
    .unwrap();

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
