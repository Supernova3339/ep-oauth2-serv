#!/bin/sh
set -e

# Check if required environment variables are set
if [ -z "$EASYPANEL_URL" ]; then
  echo "Error: EASYPANEL_URL environment variable is not set"
  exit 1
fi

if [ -z "$SESSION_SECRET" ] && [ "$NODE_ENV" = "production" ]; then
  echo "Warning: SESSION_SECRET is not set in production mode. Using a default value (not recommended for production)."
fi

# Set proper permissions for the data directory
if [ ! -d "/app/data" ]; then
  mkdir -p /app/data
fi
chmod 755 /app/data

# Execute the main command
exec "$@"