# Database Schema

## users

| Column        | Type      | Constraints                  |
|---------------|-----------|------------------------------|
| user_id       | UUID      | PRIMARY KEY, auto-generated  |
| username      | VARCHAR   | NOT NULL, UNIQUE             |
| password_hash | VARCHAR   | NOT NULL                     |
| public_key    | VARCHAR   | NOT NULL                     |
| created_at    | TIMESTAMP | NOT NULL, default NOW()      |

## messages

| Column             | Type      | Constraints                        |
|--------------------|-----------|------------------------------------|
| message_id         | UUID      | PRIMARY KEY, auto-generated        |
| sender_id          | UUID      | NOT NULL, FK → users(user_id)      |
| recipient_id       | UUID      | NOT NULL, FK → users(user_id)      |
| content_ciphertext | VARCHAR   | NOT NULL                           |
| nonce              | VARCHAR   | NOT NULL                           |
| digest             | VARCHAR   | NOT NULL                           |
| blockchain_tx_hash | VARCHAR   | nullable                           |
| created_at         | TIMESTAMP | NOT NULL, default NOW()            |

## Relationships

- `messages.sender_id` → `users.user_id` (CASCADE DELETE)
- `messages.recipient_id` → `users.user_id` (CASCADE DELETE)

## Notes

- Passwords are stored as hashes only — never plaintext.
- `content_ciphertext` stores the encrypted message payload — plaintext is never persisted.
- `nonce` is the cryptographic nonce used during encryption.
- `digest` is the message integrity hash (HMAC or similar).
- `blockchain_tx_hash` is nullable — populated once the message is anchored on-chain.
