# Easypanel OAuth2 Server

An OAuth2 authorization server that integrates with Easypanel's user authentication API.

## Features

- Standard OAuth2 authorization code flow
- Integration with Easypanel user authentication
- Client management API
- Token introspection and user info endpoints
- Finished UI
- Uses LMDB for storage

## Prerequisites

- Node.js 14+
- Access to an Easypanel instance

## Setup

1. Clone this repository
2. Install dependencies:
   ```
   npm install
   ```
3. Configure environment variables:
   ```
   export EASYPANEL_URL=http://your-easypanel-url
   export PORT=3000
   export SESSION_SECRET=your-secure-session-secret
   export API_TOKEN=easypanel-api-token
   ```
4. Build the project:
   ```
   npm run build
   ```
5. Start the server:
   ```
   npm start
   ```

## Project Structure

- `src/index.ts` - Main application file with OAuth2 server implementation
- `views/` - EJS templates for the OAuth2 UI
- `dist/` - Compiled JavaScript files

## OAuth2 Endpoints

- **Authorization Endpoint**: `/oauth/authorize`
- **Token Endpoint**: `/oauth/token`
- **Token Introspection**: `/oauth/introspect`
- **User Info**: `/oauth/userinfo`

## Client Management API

- `GET /api/clients` - List all OAuth clients
- `POST /api/clients` - Create a new OAuth client
- `GET /api/clients/:id` - Get a specific OAuth client
- `DELETE /api/clients/:id` - Delete an OAuth client

## Development

For development with hot-reloading:

```
npm run dev
```

## Security Considerations

- Always use HTTPS in production
- Set a strong SESSION_SECRET
- Periodically rotate client secrets for production clients

## License

MIT