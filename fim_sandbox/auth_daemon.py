#!/usr/bin/env python3
# Sovereign PAM Authentication Microservice
import hmac, hashlib, secrets

def verify_token(user_token, stored_hash):
    computed = hmac.new(b"sovereign_secret_salt", user_token.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed, stored_hash)
