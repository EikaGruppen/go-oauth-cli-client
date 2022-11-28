package oauth

import (
	"fmt"
	"net/url"
	"strings"
)

type authorizeRequest struct {
	url *url.URL
	redirectUri *url.URL
	state string
	codeVerifier string
}

func authorizeUrl(opts Options, port int) (request authorizeRequest, err error) {

	request.state, err = generateState()
	if err != nil {
		return authorizeRequest{}, err
	}

	codeVer, err := createCodeVerifier()
	if err != nil {
		return authorizeRequest{}, err
	}

	codeChallange := codeVer.codeChallengeS256()
	request.codeVerifier = codeVer.String()

	if opts.RedirectUri != nil && *opts.RedirectUri != (url.URL{}) {
		request.redirectUri = opts.RedirectUri
	} else {
		redirect, err := url.Parse(fmt.Sprintf("http://localhost:%d", port))
		if err != nil {
			return authorizeRequest{}, err
		}
		request.redirectUri = redirect.JoinPath("/oauth/callback")
	}

	request.url, err = url.Parse(opts.AuthorizationEndpoint)
	if err != nil {
		return authorizeRequest{}, err
	}
	q := url.Values{
		"client_id":             {opts.ClientId},
		"redirect_uri":          {request.redirectUri.String()},
		"response_type":         {"code"},
		"code_challenge":        {codeChallange},
		"code_challenge_method": {"S256"},
		"state":                 {request.state},
		"scope":                 {strings.Join(opts.Scopes, " ")},
	}

	for k, v := range opts.AuthorizationExtParams {
		q.Set(k, v)
	}
	request.url.RawQuery = q.Encode()
	return request, err
}



