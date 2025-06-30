# Manual Test Commands for Solana HTTP Server (localhost)
# Copy and paste these commands one by one

# 1. Health check
curl http://127.0.0.1:8080/health

# 2. Generate keypair (run multiple times to get different keys)
curl -X POST http://127.0.0.1:8080/keypair

# 3. Create token (replace with real addresses from step 2)
curl -X POST http://127.0.0.1:8080/token/create \
  -H "Content-Type: application/json" \
  -d '{
    "mintAuthority": "PASTE_PUBKEY_HERE",
    "mint": "PASTE_ANOTHER_PUBKEY_HERE",
    "decimals": 6
  }'

# 4. Mint tokens (replace with real addresses)
curl -X POST http://127.0.0.1:8080/token/mint \
  -H "Content-Type: application/json" \
  -d '{
    "mint": "MINT_ADDRESS",
    "destination": "DEST_ADDRESS",
    "authority": "AUTH_ADDRESS",
    "amount": 1000000
  }'

# 5. Sign message (replace SECRET_KEY with real secret from keypair)
curl -X POST http://127.0.0.1:8080/message/sign \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Hello Solana!",
    "secret": "SECRET_KEY_FROM_KEYPAIR"
  }'

# 6. Verify message (replace with real signature and pubkey from step 5)
curl -X POST http://127.0.0.1:8080/message/verify \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Hello Solana!",
    "signature": "SIGNATURE_FROM_SIGN",
    "pubkey": "PUBLIC_KEY"
  }'

# 7. Send SOL (replace with real addresses)
curl -X POST http://127.0.0.1:8080/send/sol \
  -H "Content-Type: application/json" \
  -d '{
    "from": "SENDER_ADDRESS",
    "to": "RECIPIENT_ADDRESS",
    "lamports": 100000
  }'

# 8. Send tokens (replace with real addresses)
curl -X POST http://127.0.0.1:8080/send/token \
  -H "Content-Type: application/json" \
  -d '{
    "destination": "DEST_ADDRESS",
    "mint": "MINT_ADDRESS",
    "owner": "OWNER_ADDRESS",
    "amount": 50000
  }'

# 9. Test error handling (should return error)
curl -X POST http://127.0.0.1:8080/token/create \
  -H "Content-Type: application/json" \
  -d '{
    "mintAuthority": "invalid_key",
    "mint": "also_invalid",
    "decimals": 6
  }'