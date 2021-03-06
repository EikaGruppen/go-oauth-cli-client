# go-oauth-cli-client

Add MFA/2FA support in your CLI for IDPs that support [OAuth 2.0 Authorization Code Flow](https://datatracker.ietf.org/doc/html/rfc6749)

## Features

- MFA/2FA with minimal user interaction
  - If eg. Active Directory is used for other services as well, the user is often logged in in the browser already, and can close the browser after the token exchange is done in the background
- Starts temporary local server with callback endpoint to receive the `code`, and exchange it with a `token`
- State verification
- Includes the recommended [PKCE - Proof Key for Code Exchange](https://datatracker.ietf.org/doc/html/rfc7636) extension
- Cross platform default browser invocation
- Zero dependencies

## Usage

### Configure OAuth Client in the OAuth server

```yaml
client_id: "my_cli"
redirect_uris: ["http://localhost"]
```

### Get this library
```
go get github.com/EikaGruppen/go-oauth-cli-client
```

### Use it

```go 
opts := oauth.Options{
  AuthorizationEndpoint: "https://the.oauth.server.com/authorize",
  TokenEndpoint: "https://the.oauth.server.com/token",
  ClientId: "my_cli",
  ClientSecret: "my_cli_secret", // optional
  AuthorizationExtParams: map[string]string{"scope": "openid"}, // optional
}

tokenResponse, err := oauth.AuthorizationCodeFlow(opts) // will open browser for user to do MFA, and show callback page there when done
if err != nil {
  // handle
}

fmt.Println(tokenResponse.AccessToken)
fmt.Println(tokenResponse.IdToken) // optional
fmt.Println(tokenResponse.RefreshToken) // optional
fmt.Println(tokenResponse.ExpiresIn)

// store tokens safely, and use them to authorize towards the service
```

Callback page will let the user know whether the auth was successful or not, and that they may close the page and go back to the terminal:

```
+----------------------------------------------------------------+
|   +---------------------------------------------------+        |
|   | 🔍️ |  http://localhost:8080/oauth/callback        |        |
|   +---------------------------------------------------+        |
|                                                                |
|                  Logged in successfully!                       |
|                                                                |
|           _You may now close this browser window_              |
|                                                                |
|                        [ close ]                               |
|                                                                |
+----------------------------------------------------------------+
```

#### Redirect URI

By default, `http://localhost:<choosen port>/oauth/callback` will be used. This can be overridden by setting `redirectUri`:

```go
redirectUri, err := url.Parse("https://my-url.com/the/callback")
// handle err

opts := oauth.Options{
  // ...
  redirectUri: redirectUri,
  // ...
}
```
