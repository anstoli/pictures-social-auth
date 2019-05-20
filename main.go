package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"github.com/julienschmidt/httprouter"
	"github.com/rs/cors"
	"github.com/tohast/pictures-social-auth/jwt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	gojosejwt "gopkg.in/square/go-jose.v2/jwt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	port                 = flag.Int("port", 80, "Port to listen for incoming HTTP connections.")
	jwtSigningPublicKey  = flag.String("jwt-sig-public", "/var/secrets/jwt/jwk_sig_RS512_prod.pub", "Location of public key for validating JWTs. The key should be RSA SHA 512 key in JWK format.")
	jwtSigningPrivateKey = flag.String("jwt-sig-private", "/var/secrets/jwt/jwk_sig_RS512_prod", "Location of private key for signing JWTs. The key should be RSA SHA 512 key in JWK format.")
	googleOauthConfig    = flag.String("google-oauth-config", "/var/secrets/google/google_oauth_config.json", "Location of Google Oauth config file in JSON format.")
	siteMainUrl          = flag.String("site-main-url", "https://www.plehova.art", "Absolute path of the site.")
	siteMainDomain       = flag.String("site-main-domain", "plehova.art", "Domain to set cookie for.")
	googleAuthReturnUrl  = flag.String("google-auth-return-url", "https://pages.plehova.art", "Host of Google auth return url.")
	authors = flag.String("authors", "astoliarskyi@gmail.com", "List of emails of users who should have access to author section of the site.")
)

func main() {
	setLogger()
	log.Print("Starting social-auth-service...")
	flag.Parse()

	googleCfg, err := googleConfigFromJsonFile(*googleOauthConfig)
	if err != nil {
		log.Fatal(err)
	}
	googleCtx := context.Background()

	jwtTokenTransformer, err := newJwtTokenTransformer()
	if err != nil {
		log.Fatal(err)
	}

	err = createHttpServer(googleCtx, googleCfg, jwtTokenTransformer)
	if err != nil {
		log.Fatal(err)
	}
}

func newJwtTokenTransformer() (*jwt.TokenTransformer, error) {
	sigPubKey, err := ioutil.ReadFile(*jwtSigningPublicKey)
	if err != nil {
		return nil, err
	}
	sigPrivKey, err := ioutil.ReadFile(*jwtSigningPrivateKey)
	if err != nil {
		return nil, err
	}
	return jwt.New(&jwt.Config{
		SigPublicKey:  sigPubKey,
		SigPrivateKey: sigPrivKey,
	})
}

func setLogger() {
	log.SetFlags(log.Ldate | log.Ltime | log.Llongfile)
}

func googleConfigFromJsonFile(file string) (*oauth2.Config, error) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}
	c, err := google.ConfigFromJSON(data, "https://www.googleapis.com/auth/userinfo.email", "openid")
	if err != nil {
		return nil, err
	}
	c.RedirectURL = *googleAuthReturnUrl + "/auth/google/return"
	return c, nil
}

func createHttpServer(googleOauthContext context.Context, googleOauthConf *oauth2.Config, jwtTokenTransformer *jwt.TokenTransformer) error {
	mux := httprouter.New()

	authorsSlice := strings.Split(*authors, ",")

	mux.GET("/user", getUserInfo(jwtTokenTransformer))
	mux.GET("/auth/google", logIn(googleOauthConf))
	mux.GET("/auth/google/return", logInReturn(googleOauthContext, googleOauthConf, jwtTokenTransformer, authorsSlice))

	// TODO check if required in production while resources are served from CDN
	// Add CORS support (Cross Origin Resource Sharing)
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000"},
		AllowCredentials: true,
		AllowedMethods:   []string{"GET", "POST", "PUT"},
	})

	server := http.Server{
		Addr:    "0.0.0.0:" + strconv.Itoa(*port),
		Handler: c.Handler(mux),
	}
	return server.ListenAndServe();
}

type UserInfo struct {
	Email string `json:"email"`
}

func getUserInfo(tt *jwt.TokenTransformer) func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		c, err := r.Cookie("auth-token")
		if err != nil {
			log.Print("Request to /user without auth-token has been made! This had to be stopped by ext-auth service.")
			http.Error(w, "Cannot read user info", http.StatusBadRequest)
			return
		}

		picturesClaims, err := tt.Decode(c.Value)
		if err != nil {
			log.Print(err)
			http.Error(w, "Cannot read user info", http.StatusBadRequest)
			return
		}
		userInfoJson, err := json.Marshal(UserInfo{
			Email: picturesClaims.Email,
		})
		if err != nil {
			log.Print(err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, err = w.Write(userInfoJson)
		if err != nil {
			log.Print(err)
			return
		}
	}
}

func logIn(config *oauth2.Config) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		q := r.URL.Query()
		state := q.Get("state")
		url := config.AuthCodeURL(state)
		http.Redirect(w, r, url, http.StatusSeeOther)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("Redirecting to Google log in page"))
	}
}

type Userinfo struct {
	Id    string `json:"id"`
	Email string `json:"email"`
}

func logInReturn(ctx context.Context, conf *oauth2.Config, jwtTokenTransformer *jwt.TokenTransformer, authors []string) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		q := r.URL.Query()
		_ = q.Get("state")
		code := q.Get("code")
		if code == "" {
			log.Print("code parameter is empty")
			http.Error(w, "Request should have 'code' request parameter", http.StatusBadRequest)
			return
		}
		tok, err := conf.Exchange(ctx, code)
		if err != nil {
			log.Print(err)
			http.Error(w, "Error requesting user info. Please retry later.", http.StatusInternalServerError)
			return
		}

		client := conf.Client(ctx, tok)
		infoResp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
		if err != nil {
			log.Print(err)
			http.Error(w, "Error requesting user info. Please retry later.", http.StatusInternalServerError)
			return
		}

		decoder := json.NewDecoder(infoResp.Body)
		var u Userinfo
		err = decoder.Decode(&u)
		if err != nil {
			log.Print(err)
			http.Error(w, "Error requesting user info. Please retry later.", http.StatusInternalServerError)
			return
		}

		csrfToken, err := generateCsrfToken()
		if err != nil {
			log.Print(err)
			http.Error(w, "Server logic error.", http.StatusInternalServerError)
			return
		}
		csrfTokenHashed := sha256.Sum256(csrfToken)
		var role string
		if contains(authors, u.Email) {
			role = "author";
		} else {
			role = "client";
		}

		authToken, err := jwtTokenTransformer.Encode(
			&jwt.PicturesClaims{
				Claims:        &gojosejwt.Claims{},
				Email:         u.Email,
				CsrfTokenHash: encodeBytesToString(csrfTokenHashed[:]),
				Role: role,
			})
		if err != nil {
			log.Print(err)
			http.Error(w, "Server logic error.", http.StatusInternalServerError)
			return
		}

		expireInAYear := time.Now().AddDate(1, 0, 0)

		authTokenCookie := &http.Cookie{
			Name:  "auth-token",
			Value: authToken,
			// TODO set "Secure: true" after using HTTPS
			Secure:   false,
			HttpOnly: true,
			Path:     "/",
			Domain:   *siteMainDomain,
			Expires:  expireInAYear,
		}
		http.SetCookie(w, authTokenCookie)

		csrfTokenCookie := &http.Cookie{
			Name:  "csrf-token",
			Value: encodeBytesToString(csrfToken),
			// TODO set "Secure: true" after using HTTPS
			Secure:   false,
			HttpOnly: false,
			Path:     "/",
			Domain:   *siteMainDomain,
			Expires:  expireInAYear,
		}
		http.SetCookie(w, csrfTokenCookie)

		http.Redirect(w, r, *siteMainUrl, http.StatusSeeOther)
	}
}

func contains(values []string, s string) bool {
	for _, v := range values {
		if v == s {
			return true
		}
	}
	return false
}

func generateCsrfToken() ([]byte, error) {
	t := make([]byte, 64)
	_, err := rand.Read(t)
	if err != nil {
		log.Fatal(err)
	}
	return t, err
}

func encodeBytesToString(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
