package evesso

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	LIVE_SERVER = "https://login.eveonline.com"
	TEST_SERVER = "https://sisilogin.testeveonline.com"
)

type SingleSignOn struct {
	ClientID    string
	SecretKey   string
	RedirectURI string
	Server      string
}

func (sso *SingleSignOn) Redirect(state *string, scope *string) string {
	params := url.Values{}
	params.Add("response_type", "code")
	params.Add("client_id", sso.ClientID)
	params.Add("redirect_uri", sso.RedirectURI)

	if state != nil {
		params.Add("state", *state)
	}

	if scope != nil {
		params.Add("scope", *scope)
	}

	return sso.Server + "/oauth/authorize?" + params.Encode()
}

func (sso *SingleSignOn) AccessToken(code string, refreshToken *string) (response TokenResponse, err error) {
	var grantType string
	if refreshToken == nil {
		grantType = "authorization_code"
	} else {
		grantType = "refresh_token"
	}

	params := RequestParams{}
	params.Form = &url.Values{}
	params.Form.Add("grant_type", grantType)
	params.Form.Add("code", code)
	params.Header = http.Header{}
	params.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(sso.ClientID+":"+sso.SecretKey)))

	request("POST", sso.Server+"/oauth/token", params, &response)
	if response.Error != "" {
		err = errors.New(response.ErrorDescription)
	}
	return
}

func (sso *SingleSignOn) Verify(token string) (response VerifyResponse, err error) {
	params := RequestParams{}
	params.Header = http.Header{}
	params.Header.Add("Authorization", "Bearer "+token)

	err = request("GET", sso.Server+"/oauth/verify", params, &response)
	if response.Error != "" {
		err = errors.New(response.ErrorDescription)
	}
	return
}

type RequestParams struct {
	Form   *url.Values
	Header http.Header
}

type OAuthResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type TokenResponse struct {
	OAuthResponse

	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type VerifyResponse struct {
	OAuthResponse

	CharacterID        int32
	CharacterName      string
	ExpiresOn          string
	Scopes             string
	TokenType          string
	CharacterOwnerHash string
}

func request(method string, uri string, params RequestParams, response interface{}) error {
	client := http.Client{}

	var reader io.Reader
	if params.Form != nil {
		// set the form data as body
		reader = strings.NewReader(params.Form.Encode())
		// set the content type
		params.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	}

	req, err := http.NewRequest(method, uri, reader)
	if err != nil {
		return err
	}

	for k, v := range params.Header {
		req.Header[k] = v
	}

	if res, err := client.Do(req); err != nil {
		return err
	} else {
		return json.NewDecoder(res.Body).Decode(response)
	}
}
