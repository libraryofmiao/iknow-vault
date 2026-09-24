# iKnow Vault

Zero-knowledge password-vault foundation for Cloudflare Pages + D1.

## Security model
- Vault contents are encrypted in the browser with AES-256-GCM.
- The master password never leaves the browser.
- D1 stores ciphertext, IV and salt only.
- No third-party scripts or trackers.
- Security headers and a restrictive CSP are included.

## Important
This is the first secure foundation, not a finished production password manager. Before storing real passwords, add a proper authenticated account protocol (preferably WebAuthn/passkeys plus a password-authentication protocol designed for zero-knowledge systems), encrypted backups/recovery, rate limiting, auto-lock, secure vault editing, and independent security review.

Never put a master password, encryption key, recovery secret, or Cloudflare API token in this repository.