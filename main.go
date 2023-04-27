package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/comame/readenv-go"
)

var API_HOST = "https://s1.comame.dev:6443"
var DASHBOARD_URI_HOST = "kubernetes-dashboard.kubernetes-dashboard.svc.cluster.local"
var IDP_CLIENT_SECRET = ""
var ORIGIN = "https://dash.cluster.comame.dev"

type Env struct {
	IdpClientSecret string `env:"IDP_CLIENT_SECRET"`
}

func main() {
	var env Env
	readenv.Read(&env)
	IDP_CLIENT_SECRET = env.IdpClientSecret

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	http.HandleFunc("/openid", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", generateAuthenticationInitiateURI())
		w.WriteHeader(302)
	})
	http.HandleFunc("/openid/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		code := q.Get("code")

		token, err := getOIDCToken(code)
		if err != nil {
			w.WriteHeader(400)
			w.Write([]byte(fmt.Sprintf("error: %s", err)))
			return
		}

		token, err = getKubernetesToken(token)
		if err != nil {
			w.WriteHeader(400)
			w.Write([]byte(fmt.Sprintf("error: %s", err)))
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "X-Token",
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})

		w.Header().Set("Location", ORIGIN+"/")
		w.WriteHeader(302)
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("X-Token")
		if err != nil {
			fmt.Println(err.Error())
			responseRedirectToLoginPage(w)
			return
		}
		if cookie == nil {
			responseRedirectToLoginPage(w)
			return
		}

		jwtPayload, err := extractJwtPayload(cookie.Value)
		if err != nil {
			fmt.Println(err.Error())
			responseRedirectToLoginPage(w)
			return
		}

		decodedTokenBytes, err := base64.RawStdEncoding.DecodeString(jwtPayload)
		if err != nil {
			fmt.Println(err.Error())
			responseRedirectToLoginPage(w)
			return
		}
		var decodedToken JwtPayloadPartial
		err = json.Unmarshal(decodedTokenBytes, &decodedToken)
		if err != nil {
			fmt.Println(err.Error())
			responseRedirectToLoginPage(w)
			return
		}

		now := time.Now().Unix()
		fmt.Println(now)
		fmt.Println(decodedToken)
		if now >= decodedToken.Exp {
			fmt.Println("expired")
			responseRedirectToLoginPage(w)
			return
		}

		rp := &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				newUrl, _ := url.Parse(DASHBOARD_URI_HOST)
				pr.SetURL(newUrl)
				pr.Out.Header.Set("Authorization", "Bearer "+cookie.Value)
			},
		}
		rp.ServeHTTP(w, r)
	})

	fmt.Println("start http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}

func getKubernetesToken(token string) (string, error) {
	tokenRequest := TokenRequest{
		ApiVersion: "authentication.k8s.io/v1",
		Kind:       "TokenRequest",
		Metadata: TokenMetadata{
			Namespace: "kubernetes-dashboard",
		},
		Spec: TokenSpec{
			Audiences: []string{
				"https://kubernetes.default.svc.cluster.local",
			},
			ExpirationSeconds: 60 * 60,
		},
	}
	tokenRequestStr, err := json.Marshal(tokenRequest)
	if err != nil {
		return "", err
	}

	url := API_HOST + "/api/v1/namespaces/kubernetes-dashboard/serviceaccounts/kubernetes-dashboard/token"

	req, _ := http.NewRequest("POST", url, strings.NewReader(string(tokenRequestStr)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	res, err := requestAndGetStr(req)
	if err != nil {
		return "", err
	}

	var tokenResponse TokenResponse
	err = json.Unmarshal([]byte(res), &tokenResponse)
	if err != nil {
		return "", err
	}

	return tokenResponse.Status.Token, nil
}

func getOIDCToken(code string) (string, error) {
	body := "grant_type=authorization_code&redirect_uri=" + generateRedirectURI() + "&code=" + code + "&client_secret=" + IDP_CLIENT_SECRET + "&client_id=kubernetes"
	url := "https://accounts.comame.xyz/code"

	req, _ := http.NewRequest("POST", url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := requestAndGetStr(req)
	if err != nil {
		return "", err
	}

	var codeResponse CodeResponse
	err = json.Unmarshal([]byte(res), &codeResponse)
	if err != nil {
		return "", err
	}

	valid := validateIsFilled(codeResponse)
	if !valid {
		return "", fmt.Errorf("invalid format")
	}

	return codeResponse.IdToken, nil
}

func generateRedirectURI() string {
	redirectUri := ORIGIN + "/openid/callback"
	return url.QueryEscape(redirectUri)
}

func generateAuthenticationInitiateURI() string {
	nonce := "nonce"
	return "https://accounts.comame.xyz/authenticate?client_id=kubernetes&scope=openid&response_type=code&nonce=" + nonce + "&redirect_uri=" + generateRedirectURI()
}

func responseRedirectToLoginPage(w http.ResponseWriter) {
	w.Header().Set("Location", "/openid")
	w.WriteHeader(302)
}
