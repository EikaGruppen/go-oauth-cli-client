package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
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

type tokenResponse struct {
	BearerToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
}

type oauthErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func GetAccessToken(opts Options) (accessToken string, expiry time.Time, err error) {
	return listenForCode(opts)
}

func getAccessCode(opts Options, code string, codeVerifier string, redirectUri string) (accessCode string, expiry time.Time, err error) {

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
		return "", time.Time{}, err
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", time.Time{}, err
	}
	if response.StatusCode >= 400 {
		var error oauthErrorResponse
		err = json.Unmarshal(body, &error)
		if err != nil {
			return "", time.Time{}, err
		}
		return "", time.Time{}, fmt.Errorf("Got error from OAuth Server [%s]: %s", error.Error, error.ErrorDescription)
	}
	var token tokenResponse
	err = json.Unmarshal(body, &token)
	if err != nil {
		return "", time.Time{}, err
	}
	return token.BearerToken, time.Now().Add(time.Duration(token.ExpiresIn) * time.Second), nil
}


func listenForCode(opts Options) (accessToken string, expiry time.Time, err error) {
	ctx, cancel := context.WithCancel(context.Background())

	requestState, err := generateState()
	if err != nil {
		cancel()
		return "", time.Time{}, err
	}

	codeVer, err := createCodeVerifier()
	if err != nil {
		cancel()
		return "", time.Time{}, err
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

		token, exp, err := getAccessCode(opts, code, codeVerifier, redirectUri)
		if err != nil {
			serverErrors = append(serverErrors, err)
			err = writeErrorPage(w)
			if err != nil {
				serverErrors = append(serverErrors, err)
			}
		}
		accessToken = token
		expiry = exp
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
		return "", time.Time{}, err
	}
	q := url.Values{
		"client_id":             {opts.ClientId},
		"client_secret":         {opts.ClientSecret},
		"redirect_uri":          {url.QueryEscape(redirectUri)},
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
		return "", time.Time{}, err
	}
	fmt.Printf("Default browser has been opened at %s. Please continue login in the browser\n\n", opts.AuthorizationEndpoint)

	<-ctx.Done()
	err = srv.Shutdown(context.Background())
	if err != nil {
		return "", time.Time{}, err
	}
	if len(serverErrors) > 0 {
		return "", time.Time{}, fmt.Errorf("There were local server errors: %v", serverErrors)
	}
	return accessToken, expiry, err
}
