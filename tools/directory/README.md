Directory Service (Global Usernames + Invites)

This server registers globally unique usernames and routes chat invites by username.

Run
- cd tools/directory
- npm install
- npm start

Configuration
- PORT: listening port (default 8787)
- P2PCHAT_DIRECTORY_DATA: path to the JSON data file (default tools/directory/data.json)
- P2PCHAT_DIRECTORY_ORIGINS: comma-separated browser origins allowed by CORS (default allows all origins)
- P2PCHAT_INVITE_TIMESTAMP_SKEW_MS: allowed signed invite timestamp skew in milliseconds (default 600000)

Production
- Set P2PCHAT_DIRECTORY_ORIGINS to the exact app/browser origins that should use the service.
- Mount P2PCHAT_DIRECTORY_DATA on durable storage.
- Terminate TLS at a reverse proxy or load balancer in front of this service.
- Run `npm run check` and `npm audit` before publishing a deployment image.

API
- POST /v1/challenge
- POST /v1/claim
- POST /v1/invites
- GET /v1/invites?username=...&since=...
- POST /v1/invites/:id/accept
- POST /v1/invites/:id/decline

Messages are signed with the Ed25519 identity key via the core signIdentity method.
