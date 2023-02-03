package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"sync"
	"syscall"
	"time"
)

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

	ClientTimeout time.Duration

	PortRange PortRange

	// If nil, system default browser will be used
	Browser Browser
}

type PortRange struct {
	Start int
	End   int
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

func getAuthorizationCode(opts Options, code string, authorizeRequest authorizeRequest) (tokenResponse *TokenResponse, err error) {

	urlValues := url.Values{
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"client_id":     {opts.ClientId},
		"code_verifier": {authorizeRequest.codeVerifier},
		"client_secret": {opts.ClientSecret},
		"redirect_uri":  {authorizeRequest.redirectUri.String()},
	}
	client := http.Client{
		Timeout: opts.ClientTimeout,
	}
	response, err := client.PostForm(opts.TokenEndpoint, urlValues)
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
func AuthorizationCodeFlow(opts Options) (TokenResponse, error) {
	flows, err := ConcurrentAuthorizationCodeFlow(opts.Browser, []Options{opts})
	if err != nil {
		return TokenResponse{}, nil
	}
	flow := flows[0]
	return flow.TokenResponse, flow.Error
}

func ConcurrentAuthorizationCodeFlow(browser Browser, allOpts []Options) ([]codeFlowResult, error) {

	if browser == nil {
		browser = &DefaultBrowser{}
	}

	var flows []codeFlow

	for _, opts := range allOpts {

		port := opts.PortRange.Start

		var listener net.Listener
		var err error
		for port <= opts.PortRange.End {
			listener, err = net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
			if err != nil {
				if errors.Is(err, syscall.EADDRINUSE) {
					port++
					continue
				} else {
					return nil, err
				}
			}
			defer listener.Close()
			break
		}

		authorizeRequest, err := authorizeUrl(opts, port)
		if err != nil {
			return nil, err
		}

		callbackError := make(chan error)
		token := make(chan TokenResponse)
		err = startServer(opts, authorizeRequest, listener, token, callbackError)
		if err != nil {
			return nil, err
		}

		flows = append(flows, codeFlow{
			request:       authorizeRequest,
			token:         token,
			callbackError: callbackError,
		})
	}

	return authorize(flows, browser)
}

func startServer(opts Options, authorizeRequest authorizeRequest, listener net.Listener, tokenChan chan<- TokenResponse, callbackError chan<- error) error {

	callbackHandler := func(w http.ResponseWriter, r *http.Request) {

		queryparams := r.URL.Query()
		responseState := queryparams.Get("state")
		if authorizeRequest.state != responseState {
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

		token, err := getAuthorizationCode(opts, code, authorizeRequest)
		if err != nil {
			callbackError <- err
			writeErrorPage(w, callbackError)
			return
		}
		tokenChan <- *token
		writeSuccessPage(w, callbackError)
	}

	serverMux := http.NewServeMux()
	serverMux.HandleFunc("/" +authorizeRequest.redirectUri.Path, callbackHandler)

	go func() {
		if err := http.Serve(listener, serverMux); err != nil && err != http.ErrServerClosed {
			callbackError <- fmt.Errorf("Error when starting: %w", err)
		}
	}()
	return nil
}

type codeFlow struct {
	request       authorizeRequest
	token         <-chan TokenResponse
	callbackError <-chan error
}

type codeFlowResult struct {
	TokenResponse TokenResponse
	Error         error
}

func authorize(flows []codeFlow, browser Browser) ([]codeFlowResult, error) {
	var authorizeUrls []*url.URL
	for _, flow := range flows {
		authorizeUrls = append(authorizeUrls, flow.request.url)
	}
	var wg sync.WaitGroup
	wg.Add(len(flows))

	results := make([]codeFlowResult, len(flows))
	var browserError error

	go func() {
		err := browser.Open(authorizeUrls)
		if err != nil {
			browserError = err
		}
	}()

	for i, flow := range flows {
		go func(i int, flow codeFlow) {
			select {
			case token := <-flow.token:
				results[i] = codeFlowResult{TokenResponse: token}
			case err := <-flow.callbackError:
				results[i] = codeFlowResult{Error: fmt.Errorf("Local server error: %w", err)}
			case <-time.After(3 * time.Minute):
				results[i] = codeFlowResult{Error: errors.New("Timed out waiting for oauth token")}
			}
			wg.Done()
		}(i, flow)
	}
	wg.Wait()

	if browserError != nil {
		return nil, browserError
	}

	err := browser.Destroy()
	if err != nil {
		return nil, browserError
	}
	return results, nil
}
