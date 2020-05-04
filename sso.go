/*
Copyright 2019 Christian Banse

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package evesso is the main package of this library.
package evesso

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
)

var set *jwk.Set

const (
	// LiveServer contains the url of the EVE live server.
	LiveServer = "https://login.eveonline.com"

	// TestServer contains the url of the EVE test server.
	TestServer = "https://sisilogin.testeveonline.com"
)

// SingleSignOn is a structure containing required credentials and
// settings to use the EVE SSO system.
type SingleSignOn struct {
	ClientID    string
	SecretKey   string
	RedirectURI string
	Server      string
}

// Redirect constructs an OAuth redirect url given a certain state and scope.
func (sso *SingleSignOn) Redirect(state string, scope *string) string {
	params := url.Values{}
	params.Add("response_type", "code")
	params.Add("client_id", sso.ClientID)
	params.Add("redirect_uri", sso.RedirectURI)

	params.Add("state", state)

	if scope != nil {
		params.Add("scope", *scope)
	}

	return sso.Server + "/v2/oauth/authorize?" + params.Encode()
}

// AccessToken requests an OAuath access token as well as additional meta information given an authorization code or a refreshToken.
func (sso *SingleSignOn) AccessToken(code string, refreshToken bool) (response TokenResponse, expiryTime time.Time, characterID int, characterName string, err error) {
	params := requestParams{}
	params.Form = &url.Values{}
	if !refreshToken {
		params.Form.Add("grant_type", "authorization_code")
		params.Form.Add("code", code)
	} else {
		params.Form.Add("grant_type", "refresh_token")
		params.Form.Add("refresh_token", code)
	}
	params.Header = http.Header{}
	params.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(sso.ClientID+":"+sso.SecretKey)))

	err = request("POST", sso.Server+"/v2/oauth/token", params, &response)
	if err != nil {
		return
	}

	if response.Error != "" {
		err = errors.New(response.ErrorDescription)
	}

	expiryTime, characterID, characterName, err = parseJwt(response.AccessToken)

	return
}

func parseJwt(s string) (expiryTime time.Time, characterID int, characterName string, err error) {
	// retrieve JWKs
	if set == nil {
		set, err = jwk.Fetch("https://login.eveonline.com/oauth/jwks")
		if err != nil {
			return
		}
	}

	// TODO: do proper validation (issue #4)
	// parse token
	var token *jwt.Token
	token, err = jwt.Parse(s, func(token *jwt.Token) (interface{}, error) {
		// get kid
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("kid is not a string")
		}

		// get key from key set
		keys := set.LookupKeyID(kid)

		if len(keys) != 1 {
			return nil, errors.New("Could not find key in JWK keys")
		}

		var key rsa.PublicKey

		err := keys[0].Raw(&key)

		return &key, err
	})
	// parse will through an error, if there is a problem
	if err != nil {
		return
	}

	// extract claims
	var claims jwt.MapClaims
	var ok bool
	if claims, ok = token.Claims.(jwt.MapClaims); !ok {
		err = errors.New("Cannot convert claims to jwt.MapClaims")
		return
	}

	sub, ok := claims["sub"].(string)
	if !ok {
		err = errors.New("Claims entry sub is not a string")
		return
	}

	characterName, ok = claims["name"].(string)
	if !ok {
		err = errors.New("Claims entry name is not a string")
		return
	}

	// parse characterID from subject
	rr := strings.SplitN(sub, ":", 3)
	if len(rr) != 3 {
		err = errors.New("Character ID could not be parsed from claims")
		return
	}

	characterID, err = strconv.Atoi(rr[2])
	if err != nil {
		return
	}

	// parse expire time
	timestamp := int64(claims["exp"].(float64))
	if err != nil {
		return
	}

	expiryTime = time.Unix(timestamp, 0)

	return
}

type requestParams struct {
	Form   *url.Values
	Header http.Header
}

// OAuthResponse is a generic OAuth response.
type OAuthResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// TokenResponse is an OAuthResponse which contains an access token and/or a a refresh token.
type TokenResponse struct {
	OAuthResponse

	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func request(method string, uri string, params requestParams, response interface{}) error {
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
