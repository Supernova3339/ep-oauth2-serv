#!/bin/bash
# Create a persistent OAuth client using the API key.
# Set CLIENT_API_KEY to match your server's CLIENT_API_KEY env var.

SERVER_URL="http://localhost:3000"
API_KEY="your-api-key-here"

curl -s -X POST "$SERVER_URL/api/clients" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "name": "My App",
    "redirectUris": ["http://localhost:8080/callback"],
    "allowedScopes": ["openid", "profile", "email"],
    "persistent": true
  }' | jq .
