#!/bin/bash

# This script demonstrates how to create a persistent OAuth client
# using curl commands against the OAuth2 server's API.

# Configuration
SERVER_URL="http://localhost:3000"
USERNAME="admin@example.com"
PASSWORD="your-password"

# Step 1: Login to get a session cookie
echo "Logging in to get session cookie..."
curl -c cookies.txt -X POST $SERVER_URL/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "email=$USERNAME" \
  --data-urlencode "password=$PASSWORD" \
  --data-urlencode "csrf_token=$(curl -s $SERVER_URL/login | grep csrf_token | sed 's/.*value="\([^"]*\)".*/\1/')"

echo -e "\n\nCreating persistent OAuth client..."
# Step 2: Create a new persistent client
curl -b cookies.txt -X POST $SERVER_URL/api/clients \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production Mobile App",
    "redirectUris": ["com.example.production://callback"],
    "allowedScopes": ["profile", "email", "openid"],
    "persistent": true
  }'

echo -e "\n\nListing all clients..."
# Step 3: List all clients to verify
curl -b cookies.txt -X GET $SERVER_URL/api/clients

# Clean up cookies file
echo -e "\n\nCleaning up..."
rm cookies.txt

echo -e "\nDone!"