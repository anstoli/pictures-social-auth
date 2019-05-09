package main

import (
	"context"
	"encoding/json"
	"flag"
	"github.com/julienschmidt/httprouter"
	"github.com/rs/cors"
	"github.com/tohast/pictures-social-auth/jwt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
)

var (
	port = flag.Int("port", 80, "Port to listen for incoming HTTP connections.")
	jwtSigningPublicKey  = flag.String("jwt-sig-public", "/etc/auth/jwt/jwk_sig_RS512_prod.pub", "Location of public key for validating JWTs. The key should be RSA SHA 512 key in JWK format.")
	jwtSigningPrivateKey = flag.String("jwt-sig-private", "/etc/auth/jwt/jwk_sig_RS512_prod", "Location of private key for signing JWTs. The key should be RSA SHA 512 key in JWK format.")
	googleOauthConfig = flag.String("google-oauth-config", "/etc/auth/google/google_oauth_config.json", "Location of Google Oauth config file in JSON format.")
	siteMainUrl = flag.String("site-main-url", "http://localhost:3000", "Absolute path of the site.")
)

func main() {
	setLogger()
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
	return google.ConfigFromJSON(data, "https://www.googleapis.com/auth/userinfo.email", "openid")
}

func createHttpServer(googleOauthContext context.Context, googleOauthConf *oauth2.Config, jwtTokenTransformer *jwt.TokenTransformer) error {
	mux := httprouter.New()

	mux.GET("/auth/google", logIn(googleOauthConf))
	mux.GET("/auth/google/return", logInReturn(googleOauthContext, googleOauthConf, jwtTokenTransformer))

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

func logInReturn(ctx context.Context, conf *oauth2.Config, jwtTokenTransformer *jwt.TokenTransformer) httprouter.Handle {
	authSaverPage, err := template.ParseFiles("auth_saver.html")
	if err != nil {
		log.Fatal(err)
	}
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		q := r.URL.Query()
		_ = q.Get("state")
		code := q.Get("code")
		if code == "" {
			http.Error(w, "Request should have 'code' request parameter", http.StatusBadRequest)
			return
		}
		tok, err := conf.Exchange(ctx, code)
		if err != nil {
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

		// 1. Create secrets to encrypt JWT
		// 2. Create JWT with email
		// 3. Create HTML page with embedded JWT that saves JWT in local storage and redirects to app main page

		token, err := jwtTokenTransformer.Encode(&jwt.Data{Email: u.Email})
		if err != nil {
			log.Print(err)
			http.Error(w, "Server logic error.", http.StatusInternalServerError)
			return
		}

		v := map[string]string{
			"Token": token,
			"Email": u.Email,
			"SiteMainUrl": *siteMainUrl,
		}
		err = authSaverPage.Execute(w, v)
		if err != nil {
			log.Print(err)
			http.Error(w, "Server logic error.", http.StatusInternalServerError)
			return
		}
	}
}
