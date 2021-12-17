package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

type PortRange struct {
	Start int
	End   int
}

type Options struct {
	AuthorizationEndpoint string
	// Extensions to the standard OAuth Parameters for the authorizaion endpoint
	AuthorizaionExtParams map[string]string
	TokenEndpoint         string

	ClientId     string
	ClientSecret string

	PortRange PortRange
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
}

type oauthErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func GetAccessToken(opts Options) (tokenResponse *TokenResponse, err error) {
	return listenForCode(opts)
}

func getAccessCode(opts Options, code string, codeVerifier string, redirectUri string) (tokenResponse *TokenResponse, err error) {

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

func listenForCode(opts Options) (tokenResponse *TokenResponse, err error) {
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

	redirectUri := fmt.Sprintf("http://localhost:%d/oauth/callback", port)

	http.HandleFunc("/oauth/callback", func(w http.ResponseWriter, r *http.Request) {

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

		token, err := getAccessCode(opts, code, codeVerifier, redirectUri)
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
	})
	srv := &http.Server{Addr: fmt.Sprintf("localhost:%d", port)}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErrors = append(serverErrors, fmt.Errorf("Local server error: %v", err))
		}
	}()

	authUrl, err := url.Parse(opts.AuthorizationEndpoint)
	if err != nil {
		return nil, err
	}
	q := url.Values{
		"client_id":             {opts.ClientId},
		"client_secret":         {opts.ClientSecret},
		"redirect_uri":          {redirectUri},
		"response_type":         {"code"},
		"code_challenge":        {codeChallange},
		"code_challenge_method": {"S256"},
		"state":                 {requestState},
	}

	for k, v := range opts.AuthorizaionExtParams {
		q.Set(k, v)
	}
	authUrl.RawQuery = q.Encode()

	err = OpenUrl(authUrl)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Default browser has been opened at %s. Please continue login in the browser\n\n", opts.AuthorizationEndpoint)

	<-ctx.Done()
	err = srv.Shutdown(context.Background())
	if err != nil {
		return nil, err
	}
	if len(serverErrors) > 0 {
		return nil, fmt.Errorf("There were local server errors: %v", serverErrors)
	}
	return tokenResponse, err
}
