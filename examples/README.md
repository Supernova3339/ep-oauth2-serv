# Easypanel OAuth2 Server Example Clients

This directory contains example clients for interacting with the Easypanel OAuth2 Server.

## Device Authorization Flow Demo

The `device-client.ts` file demonstrates how to use the Device Authorization Grant flow to authenticate with the OAuth2 server from a device with limited input capabilities, such as a CLI application, smart TV, or IoT device.

### Prerequisites

- Node.js 14 or higher
- npm or yarn

### Installation

```bash
# Install dependencies
npm install
```

### Running the Device Authorization Demo

```bash
# Run using ts-node
npm run device-demo

# Or build and run the JavaScript version
npm run build
npm run device-demo-js
```

## Flow Explanation

1. The client initiates the device authorization flow by making a request to the `/oauth/device` endpoint.
2. The server returns a device code, user code, and verification URL.
3. The client displays the user code and opens the verification URL in a browser.
4. The user enters the code in the browser and authorizes the device.
5. Meanwhile, the client polls the token endpoint until authorization is complete or an error occurs.
6. Upon successful authorization, the client receives access and refresh tokens.
7. The client uses the access token to fetch user information from the `/oauth/userinfo` endpoint.

## Customization

You can customize the following parameters in the client:

- `SERVER_URL`: The URL of the OAuth2 server
- `CLIENT_ID`: The client ID registered with the OAuth2 server
- `CLIENT_SECRET`: The client secret

## Error Handling

The client implements proper error handling according to RFC 8628:

- `authorization_pending`: The user has not yet completed the authorization
- `slow_down`: The client is polling too frequently and should increase the interval
- `expired_token`: The device code has expired
- `access_denied`: The user denied the authorization request

## TypeScript Types

The client includes TypeScript type definitions for all responses and parameters.