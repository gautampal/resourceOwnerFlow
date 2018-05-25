# resourceOwnerFlow

#### Sample NodeJS OIDC Resource Owner Flow client

## Usage

Add your Client ID and your OIDC issuer to .config.json

$npm install
$npm run resourceOwnerFlow
would start the server on the default 8000 port. 

### Endpoints

/token would retrive a valid auth token and store it for further calls
/userinfo gets users metadata
/secure endpoint demontrating bearer token autherization check
