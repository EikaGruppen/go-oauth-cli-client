package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
)

type PortRange struct {
	Start int
	End   int
}

type Options struct {
	AuthorizationEndpoint string
	Scopes                []string
	// Extensions to the standard OAuth Parameters for the authorizaion endpoint
	AuthorizationExtParams map[string]string
	TokenEndpoint          string
	RevokeEndpoint         string

	ClientId     string
	ClientSecret string

	RedirectUri *url.URL

	PortRange PortRange

	// Command used to open browser for auth
	// An interrupt signal (SIGINT) is sent to the command when the callback has received a code
	//
	// If nil, system default browser will be used
	OpenBrowser func(url *url.URL) *exec.Cmd
}

type TokenResponse struct {
	IdToken          string `json:"id_token"`
	AccessToken      string `json:"access_token"`
	ExpiresIn        int64  `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresIn int64  `json:"refresh_expires_in"`
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
	defer cancel()

	requestState, err := generateState()
	if err != nil {
		return nil, err
	}

	codeVer, err := createCodeVerifier()
	if err != nil {
		return nil, err
	}

	codeChallange := codeVer.codeChallengeS256()
	codeVerifier := codeVer.String()

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

	var cmd *exec.Cmd

	if opts.OpenBrowser != nil {
		cmd = opts.OpenBrowser(authUrl)
	}

	callbackError := make(chan error)

	callbackHandler := func(w http.ResponseWriter, r *http.Request) {

		if cmd != nil {
			err = cmd.Process.Signal(os.Interrupt)
			if err != nil {
				fmt.Println("Got error when interrupting browser process:", err.Error())
			}
		}

		queryparams := r.URL.Query()
		responseState := queryparams.Get("state")
		if requestState != responseState {
			callbackError <- errors.New("State does not match!")
			writeErrorPage(w, callbackError)
			return
		}

		code := queryparams.Get("code")
		if code == "" {
			callbackError <- errors.New("No code returned from IDP")
			writeErrorPage(w, callbackError)
			return
		}

		token, err := getAuthorizationCode(opts, code, codeVerifier, redirectUri)
		if err != nil {
			callbackError <- err
			writeErrorPage(w, callbackError)
			return
		}
		tokenResponse = token
		writeSuccessPage(w, callbackError)

		cancel()
	}

	serverMux := http.NewServeMux()
	serverMux.HandleFunc(path, callbackHandler)

	go func() {
		if err := http.ListenAndServe(fmt.Sprintf("localhost:%d", port), serverMux); err != nil && err != http.ErrServerClosed {
			callbackError <- fmt.Errorf("Error when starting: %w", err)
		}
	}()

	if cmd != nil {
		err := cmd.Start()
		if err != nil {
			return nil, fmt.Errorf("Failed to start browser with custom command: %w", err)
		}
		var exitErr error
		go func() {
			exitErr = cmd.Wait()
		}()
		select {
		case err := <-callbackError:
			return nil, fmt.Errorf("Local server error: %w", err)
		case <-ctx.Done():
		}

		if exitErr != nil {
			fmt.Println("Browser process exited with error:", exitErr.Error())
		}
	} else {
		openDefaultBrowser(authUrl)
		fmt.Printf("Default browser has been opened at %s. Please continue login in the browser\n\n", authUrl)

		select {
		case err := <-callbackError:
			return nil, fmt.Errorf("Local server error: %w", err)
		case <-ctx.Done():
		}
	}
	close(callbackError)

	return tokenResponse, err
}
