package oauth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

func Refresh(opts Options, refreshToken string) (*TokenResponse, error) {

	params := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {opts.ClientId},
		"refresh_token": {refreshToken},
	}
	response, err := http.PostForm(opts.TokenEndpoint, params)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
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
	var tokenResponse TokenResponse
	err = json.Unmarshal(body, &tokenResponse)
	return &tokenResponse, err
}
