package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

type AccessTokenRequest struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	KeyID      string `json:"key_id"`
	ClientID   string `json:"client_id"`
	IAMBaseURL string `json:"iam_base_url"`
	RealmName  string `json:"realm_name"`
	CodeVerifier  string `json:"code_verifier"`
	CodeChallenge  string `json:"code_challenge"`
	CodeMethod  string `json:"code_method"`
}

// ----- Enum benzeri key type tanımı -----
type KeyType string

const (
	KeyTypeEC  KeyType = "EC"
	KeyTypeRSA KeyType = "RSA"
)

func (k KeyType) IsValid() bool {
	return k == KeyTypeEC || k == KeyTypeRSA
}

// ----- İstek ve yanıt struct'ları -----

type KeyPairRequest struct {
	KeyType KeyType `json:"key_type"`
}

type KeyPairResponse struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

type DPoPRequest struct {
	KeyID            string                 `json:"key_id"`
	Method           string                 `json:"method"`
	URI              string                 `json:"uri"`
	AccessToken      string                 `json:"access_token,omitempty"`
	AdditionalClaims map[string]interface{} `json:"additional_claims,omitempty"`
}

type DPoPResponse struct {
	Token string `json:"dpop_token"`
}

// ----- Anahtar verisi struct'ı ve in-memory store -----

type KeyData struct {
	PrivateKey interface{} // RSA veya ECDSA olabilir
	PublicPEM  string
	CreatedAt  time.Time
}

var keyStore = make(map[string]KeyData)
var mu sync.Mutex

// ----- Yardımcı fonksiyonlar -----

func intToBase64URL(i *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(i.Bytes())
}

func computeATH(token string) string {
	hash := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// RSA veya EC key pair üretimi
func generateKeyPair(keyType KeyType) (string, KeyData, error) {
	switch keyType {
	case KeyTypeRSA:
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return "", KeyData{}, err
		}

		pubASN1, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			return "", KeyData{}, err
		}

		pubPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubASN1,
		})

		keyID := uuid.New().String()
		return keyID, KeyData{
			PrivateKey: privateKey,
			PublicPEM:  string(pubPEM),
			CreatedAt:  time.Now(),
		}, nil

	case KeyTypeEC:
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return "", KeyData{}, err
		}

		pubASN1, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			return "", KeyData{}, err
		}

		pubPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubASN1,
		})

		keyID := uuid.New().String()
		return keyID, KeyData{
			PrivateKey: privateKey,
			PublicPEM:  string(pubPEM),
			CreatedAt:  time.Now(),
		}, nil

	default:
		return "", KeyData{}, fmt.Errorf("unsupported key type: %s", keyType)
	}
}

func generateDPoPToken(privKey interface{}, method, uri, accessToken string, additionalClaims map[string]interface{}) (string, error) {
	now := time.Now().Unix()
	jti := uuid.New().String()

	var alg string
	var jwk map[string]interface{}

	switch key := privKey.(type) {
	case *rsa.PrivateKey:
		pubKey := key.PublicKey
		n := intToBase64URL(pubKey.N)
		e := intToBase64URL(big.NewInt(int64(pubKey.E)))
		alg = jwt.SigningMethodRS256.Alg()
		jwk = map[string]interface{}{
			"kty": "RSA",
			"n":   n,
			"e":   e,
			"kid": base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes())[0:8],
		}

	case *ecdsa.PrivateKey:
		pubKey := key.PublicKey
		x := intToBase64URL(pubKey.X)
		y := intToBase64URL(pubKey.Y)
		alg = jwt.SigningMethodES256.Alg()
		jwk = map[string]interface{}{
			"kty": "EC",
			"crv": "P-256",
			"x":   x,
			"y":   y,
			"kid": base64.RawURLEncoding.EncodeToString(pubKey.X.Bytes())[0:8],
		}

	default:
		return "", fmt.Errorf("unsupported private key type")
	}

	token := jwt.New(jwt.GetSigningMethod(alg))
	claims := token.Claims.(jwt.MapClaims)

	claims["jti"] = jti
	claims["htm"] = strings.ToUpper(method)
	claims["htu"] = uri
	claims["iat"] = now
	claims["exp"] = now + 10

	if accessToken != "" {
		claims["ath"] = computeATH(accessToken)
	}

	for k, v := range additionalClaims {
		claims[k] = v
	}

	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = jwk

	tokenStr, err := token.SignedString(privKey)
	if err != nil {
		return "", err
	}

	return tokenStr, nil
}

func parseAccessTokenRequest(r *http.Request) (AccessTokenRequest, error) {
	var req AccessTokenRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	return req, err
}

func fetchActionTokenFromIAM(req AccessTokenRequest) (string, error) {
	form := url.Values{}
	form.Add("username", req.Username)
	form.Add("client_id", req.ClientID)
	form.Add("grant_type", "password")
	form.Add("password", req.Password)
	

	mu.Lock()
	keyData, exists := keyStore[req.KeyID]
	mu.Unlock()
	if !exists {
		return "", fmt.Errorf("Key ID Not Found while getting action token")
	}

	defaultCC, defaultCM, _ := initializePCKE(req)
	iamURL := req.IAMBaseURL + "/realms/" + req.RealmName + "/protocol/openid-connect/token?cc=" + defaultCC+ "&cm=" + defaultCM
	dpopToken, err2 := generateDPoPToken(keyData.PrivateKey, "POST", iamURL, "", nil)
	httpReq, err := http.NewRequest("POST", iamURL, strings.NewReader(form.Encode()))
	if err != nil {
		log.Printf("[ERROR] Failed to create IAM request: %v\n", err)
		return "", fmt.Errorf("failed to create IAM request: %w", err)
	}

	if err2 != nil {
		log.Printf("[ERROR] Failed to create DPoP Token: %v\n", err2)
		return "", fmt.Errorf("failed to create DPoP Token: %w", err2)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("DPoP", dpopToken)
	
	log.Printf("Password " + req.Password)
	log.Printf("Dpop token " + dpopToken)


	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		log.Printf("[ERROR] IAM request failed: %v\n", err)
		return "", fmt.Errorf("IAM request failed: %w", err)
	}
	defer resp.Body.Close()

	log.Printf("[RESPONSE] IAM status: %d\n", resp.StatusCode)

	if resp.StatusCode != http.StatusForbidden {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Printf("[ERROR] IAM non-OK response: %s\n", string(bodyBytes))
		return "", fmt.Errorf("IAM responded with status %d", resp.StatusCode)
	}

	var iamResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&iamResp); err != nil {
		log.Printf("[ERROR] Invalid IAM response JSON: %v\n", err)
		return "", fmt.Errorf("invalid IAM response JSON: %w", err)
	}


	token, ok := iamResp["actionToken"].(string)
	if !ok || token == "" {
		log.Println("[ERROR] actionToken missing in IAM response")
		return "", fmt.Errorf("actionToken missing in IAM response")
	}
	return token, nil
}

const (
	verifierLength = 128
	alphanumeric   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

func generateCodeVerifier(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	for i := range bytes {
		bytes[i] = alphanumeric[bytes[i]%byte(len(alphanumeric))]
	}

	return string(bytes), nil
}

func generateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func initializePCKE(req AccessTokenRequest)(string, string, string){
	defaultCC := "4fa3G5w5LHr7y6GKEpnzFmFlNqwrbwcwetQL7QBwjHI"
	defaultCM := "S256"
	defaultCV := "l2zmqs0nev55ss76b0pfm1aj8thipgnlspfzv2xapulfb78j1dckf5vqd2n0ur32ybfkf4pr3lpj8jor08sgfl8f1634536yilywr93p059pmyi7pj7wdbd7g5avljk6"

	if(req.CodeChallenge != ""){
		defaultCC = req.CodeChallenge
	}

	if(req.CodeMethod != ""){
		defaultCM = req.CodeMethod
	}

	
	if(req.CodeVerifier != ""){
		defaultCV = req.CodeVerifier
	}

	return defaultCC, defaultCM, defaultCV
}

func sendKeycloakRequest(req AccessTokenRequest, actionToken, dpopToken string) (*http.Response, string, error) {
	defaultCC, defaultCM, defaultCV := initializePCKE(req)
	iamURL := req.IAMBaseURL + "/realms/" + req.RealmName + "/login-actions/action-token?cv="+defaultCV+"&ecc="+defaultCC+"&ecm="+defaultCM+"&key=" + actionToken

	httpReq, err := http.NewRequest("GET", iamURL, nil)
	if err != nil {
		log.Printf("[ERROR] Failed to create Keycloak request: %v\n", err)
		return nil, "", fmt.Errorf("failed to create request: %v", err)
	}
	httpReq.Header.Set("DPoP", dpopToken)

	client := &http.Client{}
	resp, err := client.Do(httpReq)
	if err != nil {
		log.Printf("[ERROR] Failed to send Keycloak request: %v\n", err)
		return nil, "", fmt.Errorf("failed to send request: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		log.Printf("[ERROR] Keycloak non-OK response: %s\n", string(bodyBytes))
		return nil, "", fmt.Errorf("keycloak request failed with status %d", resp.StatusCode)
	}

	var keycloakResp map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&keycloakResp)
	if err != nil {
		resp.Body.Close()
		log.Printf("[ERROR] Failed to decode Keycloak response: %v\n", err)
		return nil, "", fmt.Errorf("failed to parse keycloak response: %v", err)
	}

	accessToken, ok := keycloakResp["access_token"].(string)
	if !ok || accessToken == "" {
		log.Println("[ERROR] access_token missing in Keycloak response")
		return nil, "", fmt.Errorf("access_token missing in keycloak response")
	}

	return resp, accessToken, nil
}

// ----- HTTP Handlers -----

func rootHandler(w http.ResponseWriter, r *http.Request) {
	doc := `
# 🛡️ DPoP Token API Documentation

Base URL: http://localhost:5000

## 📌 Root

**GET /**  
Returns a welcome message and lists available endpoints.

---

## 🔑 Generate Key Pair

**POST /generate-keypair**

Generates a new EC or RSA key pair.

Request:
{
  "key_type": "EC" // or "RSA"
}

Response:
{
  "key_id": "uuid-string",
  "public_key": "-----BEGIN PUBLIC KEY-----..."
}

---

## 🔐 Generate DPoP Token

**POST /generate-dpop**

Creates a DPoP token using a stored key.

Request:
{
  "key_id": "uuid-string",
  "method": "GET",
  "uri": "https://example.com",
  "access_token": "optional",
  "additional_claims": { "scope": "openid" }
}

Response:
{
  "dpop_token": "eyJhbGciOi..."
}

---

## 🎫 Get Access Token

**POST /get-access-token**

Authenticates to Keycloak using DPoP.

Request:
{
  "username": "user",
  "key_id": "uuid-string",
  "client_id": "client",
  "iam_base_url": "https://iam.example.com",
  "realm_name": "myrealm"
}

Response:
{
  "access_token": "eyJ..."
}
`
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, doc)
}

func generateKeypairHandler(w http.ResponseWriter, r *http.Request) {
	var req KeyPairRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if !req.KeyType.IsValid() {
		http.Error(w, "Invalid key_type: must be 'EC' or 'RSA'", http.StatusBadRequest)
		return
	}

	keyID, keyData, err := generateKeyPair(req.KeyType)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	mu.Lock()
	keyStore[keyID] = keyData
	mu.Unlock()

	w.Header().Set("Content-Type", "application/json")

	resp := KeyPairResponse{KeyID: keyID, PublicKey: keyData.PublicPEM}
	json.NewEncoder(w).Encode(resp)
}

func generateDPoPHandler(w http.ResponseWriter, r *http.Request) {
	var req DPoPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	mu.Lock()
	keyData, exists := keyStore[req.KeyID]
	mu.Unlock()
	if !exists {
		http.Error(w, "Key not found", http.StatusNotFound)
		return
	}

	token, err := generateDPoPToken(keyData.PrivateKey, req.Method, req.URI, req.AccessToken, req.AdditionalClaims)
	if err != nil {
		http.Error(w, "Failed to create DPoP token", http.StatusInternalServerError)
		return
	}

	resp := DPoPResponse{Token: token}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func getAccessTokenHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Access Token request verilerini al
	req, err := parseAccessTokenRequest(r)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// 2. KeyData'yı al
	mu.Lock()
	keyData, exists := keyStore[req.KeyID]
	mu.Unlock()
	if !exists {
		http.Error(w, "Key not found", http.StatusNotFound)
		return
	}

	// 3. IAM'den actionToken'ı al
	actionToken, err := fetchActionTokenFromIAM(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	// 4. DPoP token'ı oluştur
	uri := req.IAMBaseURL + "/realms/" + req.RealmName + "/login-actions/action-token"
	dpopToken, err := generateDPoPToken(keyData.PrivateKey, "GET", uri, "", nil)
	if err != nil {
		http.Error(w, "Failed to generate DPoP token", http.StatusInternalServerError)
		return
	}

	// 5. Keycloak'a GET isteğini gönder
	keycloakResp, accessToken, err := sendKeycloakRequest(req, actionToken, dpopToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	// 6. Keycloak yanıtını istemciye döndür
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(keycloakResp.StatusCode)

	// Access token'ı JSON olarak kullanıcıya döndür
	resp := map[string]string{
		"access_token": accessToken,
	}
	json.NewEncoder(w).Encode(resp)
}

// ----- main -----

func main() {
	router := mux.NewRouter()
	router.HandleFunc("/", rootHandler).Methods("GET")
	router.HandleFunc("/generate-keypair", generateKeypairHandler).Methods("POST")
	router.HandleFunc("/generate-dpop", generateDPoPHandler).Methods("POST")
	router.HandleFunc("/get-access-token", getAccessTokenHandler).Methods("POST")

	fmt.Println("Server is running on port 5000")
	log.Fatal(http.ListenAndServe(":5000", router))
}
