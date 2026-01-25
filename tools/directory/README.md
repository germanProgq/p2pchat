Directory Service (Global Usernames + Invites)

This server registers globally unique usernames and routes chat invites by username.

Run
- cd tools/directory
- npm install
- npm start

Configuration
- PORT: listening port (default 8787)
- P2PCHAT_DIRECTORY_DATA: path to the JSON data file (default tools/directory/data.json)

API
- POST /v1/challenge
- POST /v1/claim
- POST /v1/invites
- GET /v1/invites?username=...&since=...
- POST /v1/invites/:id/accept
- POST /v1/invites/:id/decline

Messages are signed with the Ed25519 identity key via the core signIdentity method.
