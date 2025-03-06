# Docker Setup for Easypanel OAuth2 Server

This document provides instructions for running the Easypanel OAuth2 Server using Docker.

## Quick Start

1. Clone the repository:
   ```
   git clone https://github.com/supernova3339/ep-oauth2-serv.git
   cd easypanel-oauth2-server
   ```

2. Configure environment variables in the `docker-compose.yml` file:
    - `EASYPANEL_URL`: URL of your Easypanel instance (required)
    - `SESSION_SECRET`: A secure random string for session encryption
    - `API_TOKEN`: Your Easypanel API token for authentication

3. Build and start the container:
   ```
   docker-compose up -d
   ```

4. Access the OAuth2 server at http://localhost:3000

## Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `EASYPANEL_URL` | URL of your Easypanel instance | None | Yes |
| `SESSION_SECRET` | Secret key for session encryption | None | Yes (in production) |
| `API_TOKEN` | Easypanel API token | None | Yes |
| `PORT` | Port to run the server on | 3000 | No |
| `NODE_ENV` | Node environment | production | No |

## Persistent Data

Data is stored in a Docker volume named `easypanel-oauth2-data`. This includes:

- OAuth clients
- Authorization codes
- Access tokens
- Refresh tokens
- Device codes

To backup this data:

```bash
docker run --rm -v easypanel-oauth2-data:/data -v $(pwd):/backup alpine tar -zcf /backup/oauth2-data-backup.tar.gz /data
```

To restore from a backup:

```bash
docker run --rm -v easypanel-oauth2-data:/data -v $(pwd):/backup alpine sh -c "rm -rf /data/* && tar -xzf /backup/oauth2-data-backup.tar.gz -C /"
```

## Building the Docker Image Manually

To build the Docker image without docker-compose:

```bash
docker build -t easypanel-oauth2-server .
```

To run the container:

```bash
docker run -d \
  --name easypanel-oauth2-server \
  -p 3000:3000 \
  -e EASYPANEL_URL=https://your-easypanel-url \
  -e SESSION_SECRET=your-secret \
  -e API_TOKEN=your-token \
  -v easypanel-oauth2-data:/app/data \
  easypanel-oauth2-server
```

## Development with Docker

For development, you can use the following compose command to enable hot-reloading:

```bash
docker-compose -f docker-compose.dev.yml up
```

This mounts your local source code into the container and runs the application in development mode.