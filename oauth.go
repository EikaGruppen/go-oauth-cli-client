package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

type PortRange struct {
	Start int
	End   int
}

type Options struct {
	AuthorizationEndpoint string
	// Extensions to the standard OAuth Parameters for the authorizaion endpoint
	Scopes                 []string
	AuthorizationExtParams map[string]string
	TokenEndpoint          string

	ClientId     string
	ClientSecret string

	RedirectUri *url.URL

	PortRange PortRange
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	IdToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

type oauthErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func AuthorizationCodeFlow(opts Options) (tokenResponse *TokenResponse, err error) {
	return listenForAuthorizationCode(opts)
}

func getAuthorizationCode(opts Options, code string, codeVerifier string, redirectUri string) (tokenResponse *TokenResponse, err error) {

	urlValues := url.Values{
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"client_id":     {opts.ClientId},
		"code_verifier": {codeVerifier},
		"client_secret": {opts.ClientSecret},
		"redirect_uri":  {redirectUri},
	}
	response, err := http.PostForm(opts.TokenEndpoint, urlValues)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 400 {
		var error oauthErrorResponse
		err = json.Unmarshal(body, &error)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("Got error from OAuth Server [%s]: %s", error.Error, error.ErrorDescription)
	}
	var token TokenResponse
	err = json.Unmarshal(body, &token)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

func listenForAuthorizationCode(opts Options) (tokenResponse *TokenResponse, err error) {
	ctx, cancel := context.WithCancel(context.Background())

	requestState, err := generateState()
	if err != nil {
		cancel()
		return nil, err
	}

	codeVer, err := createCodeVerifier()
	if err != nil {
		cancel()
		return nil, err
	}

	codeChallange := codeVer.codeChallengeS256()
	codeVerifier := codeVer.String()

	var serverErrors []error

	port := opts.PortRange.Start // TODO check for open ports

	var redirectUri string
	var path string

	if opts.RedirectUri != nil && *opts.RedirectUri != (url.URL{}) {
		redirectUri = opts.RedirectUri.String()
		path = opts.RedirectUri.Path
	} else {
		path = "/oauth/callback"
		redirectUri = fmt.Sprintf("http://localhost:%d%s", port, path)
	}

	callbackHandler := func(w http.ResponseWriter, r *http.Request) {

		queryparams := r.URL.Query()
		responseState := queryparams.Get("state")
		if requestState != responseState {
			serverErrors = append(serverErrors, errors.New("State does not match!"))
			return
		}

		code := queryparams.Get("code")
		if code == "" {
			serverErrors = append(serverErrors, errors.New("No code returned from oauth"))
			return
		}

		token, err := getAuthorizationCode(opts, code, codeVerifier, redirectUri)
		if err != nil {
			serverErrors = append(serverErrors, err)
			err = writeErrorPage(w)
			if err != nil {
				serverErrors = append(serverErrors, err)
			}
		}
		tokenResponse = token
		err = writeSuccessPage(w)
		if err != nil {
			serverErrors = append(serverErrors, err)
		}

		cancel()
	}

	serverMux := http.NewServeMux()
	serverMux.HandleFunc(path, callbackHandler)

	go func() {
		if err := http.ListenAndServe(fmt.Sprintf("localhost:%d", port), serverMux); err != nil && err != http.ErrServerClosed {
			serverErrors = append(serverErrors, fmt.Errorf("Local server error: %v", err))
		}
	}()

	authUrl, err := url.Parse(opts.AuthorizationEndpoint)
	if err != nil {
		return nil, err
	}
	q := url.Values{
		"client_id":             {opts.ClientId},
		"redirect_uri":          {redirectUri},
		"response_type":         {"code"},
		"code_challenge":        {codeChallange},
		"code_challenge_method": {"S256"},
		"state":                 {requestState},
		"scope":                 {strings.Join(opts.Scopes, " ")},
	}

	for k, v := range opts.AuthorizationExtParams {
		q.Set(k, v)
	}
	authUrl.RawQuery = q.Encode()

	err = OpenUrl(authUrl)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Default browser has been opened at %s. Please continue login in the browser\n\n", authUrl)

	<-ctx.Done()
	if len(serverErrors) > 0 {
		return nil, fmt.Errorf("There were local server errors: %v", serverErrors)
	}
	return tokenResponse, err
}
