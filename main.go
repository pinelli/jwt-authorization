package main

// using asymmetric crypto/RSA keys

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"log"
	"net/http"
	"time"
)

var hmacSampleSecret = []byte("qwerty")

// setup the handlers and start listening to requests
func main() {
	http.HandleFunc("/token", TokenHandler)                       //authencticate
	http.HandleFunc("/resource", authMiddleware(ResourceHandler)) //get the resource

	log.Println("Listening to :8080...")
	http.ListenAndServe(":8080", nil)
}

var ResourceHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("token")
	fmt.Println("Got token: ", cookie.Value)

	payload, _ := json.Marshal("This is resource!")

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(payload))
})

var TokenHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	token := signToken()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Set-Cookie", "token="+token)
	resp, _ := json.Marshal("You are authenticated")
	w.Write(resp)
})

func signToken() string {
	// Create a new token object, specifying signing method and the claims
	// you would like it to contain.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"foo": "bar",
		"nbf": time.Now().Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(hmacSampleSecret)

	fmt.Println(tokenString, err)
	return tokenString
}

func retrieveClaims(tokenString string) (map[string]interface{}, bool) {
	// Parse takes the token string and a function for looking up the key. The latter is especially
	// useful if you use multiple keys for your application.  The standard is to use 'kid' in the
	// head of the token to identify which key to use, but the parsed token (head and claims) is provided
	// to the callback, providing flexibility.

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return hmacSampleSecret, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		//fmt.Println("CLAIMS: ", claims["foo"], claims["nbf"])
		return map[string]interface{}(claims), ok
	} else {
		fmt.Println(err)
		return nil, false
	}
}

func authMiddleware(next http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := r.Cookie("token")
		if err != nil {
			fmt.Println(err)
			sendUnauthorized(w, "Unauthorized. Authenticate via \"/token\"")
			return
		}

		_, ok := retrieveClaims(token.Value)
		if !ok {
			sendUnauthorized(w, "Unauthorized")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized"))
			return
		}

		next.ServeHTTP(w, r)
	})
}

func sendUnauthorized(w http.ResponseWriter, msg string) {
	w.WriteHeader(http.StatusUnauthorized)
	jsonStr, _ := json.Marshal(msg)
	w.Write(jsonStr)
}
