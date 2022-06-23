package oauth

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)


type TokenType int

const (
	ACCESS_TOKEN = iota
	REFRESH_TOKEN
)

func (t TokenType) String() string {
	return []string{
		"access_token",
		"refresh_token",
	}[t]
}


func Revoke(opts Options, tokenType TokenType, token string) error {

	params := url.Values{
		"client_id":     {opts.ClientId},
		"token":          {token},
		"token_type_hint": {tokenType.String()},
	}
	response, err := http.PostForm(opts.RevokeEndpoint, params)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}
	if response.StatusCode >= 400 {
		var error oauthErrorResponse
		err = json.Unmarshal(body, &error)
		if err != nil {
			return err
		}
		return fmt.Errorf("Got error from OAuth Server [%s]: %s", error.Error, error.ErrorDescription)
	}
	return nil
}
