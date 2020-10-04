package jwt

import (
	"crypto/rsa"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

// IdentityKey default identity key
var IdentityKey = "identity"

type JWTBody struct {
	IdentityKey       string
	Key               []byte
	SigningAlgorithm  string
	Timeout           time.Duration
	MaxRefresh        time.Duration
	PrivKeyFile       string
	PubKeyFile        string
	privKey           *rsa.PrivateKey
	pubKey            *rsa.PublicKey
	TokenLookup       string
	TokenHeadName     string
	SendCookie        bool
	CookieMaxAge      time.Duration
	SecureCookie      bool
	CookieHTTPOnly    bool
	CookieDomain      string
	SendAuthorization bool
	CookieName        string
	CookieSameSite    http.SameSite
	TimeFunc          func() time.Time
	PayloadFunc       func(data interface{}) MapClaims
	IdentityFunc      func(*gin.Context) interface{}
}

func (jb *JWTBody) JWTBodyInit() error {
	if jb.IdentityKey == "" {
		jb.IdentityKey = IdentityKey
	}

	if jb.TokenLookup == "" {
		jb.TokenLookup = "header:Authorization"
	}

	if jb.SigningAlgorithm == "" {
		jb.SigningAlgorithm = "HS256"
	}

	if jb.Timeout == 0 {
		jb.Timeout = time.Hour
	}

	if jb.TimeFunc == nil {
		jb.TimeFunc = time.Now
	}

	if jb.IdentityFunc == nil {
		jb.IdentityFunc = func(c *gin.Context) interface{} {
			claims := ExtractClaims(c)
			return claims[jb.IdentityKey]
		}
	}

	jb.TokenHeadName = strings.TrimSpace(jb.TokenHeadName)
	if len(jb.TokenHeadName) == 0 {
		jb.TokenHeadName = "Bearer"
	}

	if jb.CookieMaxAge == 0 {
		jb.CookieMaxAge = jb.Timeout
	}

	if jb.CookieName == "" {
		jb.CookieName = "jwt"
	}

	if jb.usingPublicKeyAlgo() {
		return jb.readKeys()
	}

	if jb.Key == nil {
		return ErrMissingSecretKey
	}

	return nil
}

func (jb *JWTBody) readKeys() error {
	err := jb.privateKey()
	if err != nil {
		return err
	}
	err = jb.publicKey()
	if err != nil {
		return err
	}
	return nil
}

func (jb *JWTBody) privateKey() error {
	keyData, err := ioutil.ReadFile(jb.PrivKeyFile)
	if err != nil {
		return ErrNoPrivKeyFile
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		return ErrInvalidPrivKey
	}
	jb.privKey = key
	return nil
}

func (jb *JWTBody) publicKey() error {
	keyData, err := ioutil.ReadFile(jb.PubKeyFile)
	if err != nil {
		return ErrNoPubKeyFile
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		return ErrInvalidPubKey
	}
	jb.pubKey = key
	return nil
}

func (jb *JWTBody) usingPublicKeyAlgo() bool {
	switch jb.SigningAlgorithm {
	case "RS256", "RS512", "RS384":
		return true
	}
	return false
}

func (jb *JWTBody) ParseToken(c *gin.Context) (*jwt.Token, error) {
	var token string
	var err error

	methods := strings.Split(jb.TokenLookup, ",")
	for _, method := range methods {
		if len(token) > 0 {
			break
		}
		parts := strings.Split(strings.TrimSpace(method), ":")
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])
		switch k {
		case "header":
			token, err = jb.jwtFromHeader(c, v)
		case "query":
			token, err = jb.jwtFromQuery(c, v)
		case "cookie":
			token, err = jb.jwtFromCookie(c, v)
		case "param":
			token, err = jb.jwtFromParam(c, v)
		}
	}

	if err != nil {
		return nil, err
	}

	return jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if jwt.GetSigningMethod(jb.SigningAlgorithm) != t.Method {
			return nil, ErrInvalidSigningAlgorithm
		}
		if jb.usingPublicKeyAlgo() {
			return jb.pubKey, nil
		}

		// save token string if vaild
		c.Set("JWT_TOKEN", token)

		return jb.Key, nil
	})
}

func (jb *JWTBody) jwtFromHeader(c *gin.Context, key string) (string, error) {
	authHeader := c.Request.Header.Get(key)

	if authHeader == "" {
		return "", ErrEmptyAuthHeader
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if !(len(parts) == 2 && parts[0] == jb.TokenHeadName) {
		return "", ErrInvalidAuthHeader
	}

	return parts[1], nil
}

func (jb *JWTBody) jwtFromQuery(c *gin.Context, key string) (string, error) {
	token := c.Query(key)

	if token == "" {
		return "", ErrEmptyQueryToken
	}

	return token, nil
}

func (jb *JWTBody) jwtFromCookie(c *gin.Context, key string) (string, error) {
	cookie, _ := c.Cookie(key)

	if cookie == "" {
		return "", ErrEmptyCookieToken
	}

	return cookie, nil
}

func (jb *JWTBody) jwtFromParam(c *gin.Context, key string) (string, error) {
	token := c.Param(key)

	if token == "" {
		return "", ErrEmptyParamToken
	}

	return token, nil
}

func (jb *JWTBody) GetClaimsFromJWT(c *gin.Context) (MapClaims, error) {
	token, err := jb.ParseToken(c)

	if err != nil {
		return nil, err
	}

	if jb.SendAuthorization {
		if v, ok := c.Get("JWT_TOKEN"); ok {
			c.Header("Authorization", jb.TokenHeadName+" "+v.(string))
		}
	}

	claims := MapClaims{}
	for key, value := range token.Claims.(jwt.MapClaims) {
		claims[key] = value
	}

	return claims, nil
}

func (jb *JWTBody) ParseTokenString(token string) (*jwt.Token, error) {
	return jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if jwt.GetSigningMethod(jb.SigningAlgorithm) != t.Method {
			return nil, ErrInvalidSigningAlgorithm
		}
		if jb.usingPublicKeyAlgo() {
			return jb.pubKey, nil
		}

		return jb.Key, nil
	})
}

func (jb *JWTBody) TokenGenerator(c *gin.Context, data interface{}) (string, time.Time, error) {
	token := jwt.New(jwt.GetSigningMethod(jb.SigningAlgorithm))
	claimsNow := token.Claims.(jwt.MapClaims)

	if jb.PayloadFunc != nil && data != nil {
		for key, value := range jb.PayloadFunc(data) {
			claimsNow[key] = value
		}
	}

	if claims, ok := data.(jwt.MapClaims); ok {
		for key := range claims {
			claimsNow[key] = claims[key]
		}
	}

	expire := jb.TimeFunc().UTC().Add(jb.Timeout)
	claimsNow["exp"] = expire.Unix()
	claimsNow["orig_iat"] = jb.TimeFunc().Unix()
	tokenString, err := jb.signedString(token)

	if err != nil {
		return "", time.Time{}, err
	}

	if jb.SendCookie {
		jb.CookieGenerator(c, tokenString)
	}

	return tokenString, expire, nil
}

func (jb *JWTBody) CheckIfTokenExpired(c *gin.Context) (jwt.MapClaims, error) {
	token, err := jb.ParseToken(c)

	if err != nil {
		validationErr, ok := err.(*jwt.ValidationError)
		if !ok || validationErr.Errors != jwt.ValidationErrorExpired {
			return nil, err
		}
	}

	claims := token.Claims.(jwt.MapClaims)

	origIat := int64(claims["orig_iat"].(float64))

	if origIat < jb.TimeFunc().Add(-jb.MaxRefresh).Unix() {
		return nil, ErrExpiredToken
	}

	return claims, nil
}

func (jb *JWTBody) CookieGenerator(c *gin.Context, tokenString string) {
	expireCookie := jb.TimeFunc().Add(jb.CookieMaxAge)
	maxage := int(expireCookie.Unix() - jb.TimeFunc().Unix())

	if jb.CookieSameSite != 0 {
		c.SetSameSite(jb.CookieSameSite)
	}

	c.SetCookie(
		jb.CookieName,
		tokenString,
		maxage,
		"/",
		jb.CookieDomain,
		jb.SecureCookie,
		jb.CookieHTTPOnly,
	)
}

func (jb *JWTBody) CookieExpired(c *gin.Context) {
	if jb.CookieSameSite != 0 {
		c.SetSameSite(jb.CookieSameSite)
	}

	c.SetCookie(
		jb.CookieName,
		"",
		-1,
		"/",
		jb.CookieDomain,
		jb.SecureCookie,
		jb.CookieHTTPOnly,
	)
}

func (jb *JWTBody) signedString(token *jwt.Token) (string, error) {
	var tokenString string
	var err error
	if jb.usingPublicKeyAlgo() {
		tokenString, err = token.SignedString(jb.privKey)
	} else {
		tokenString, err = token.SignedString(jb.Key)
	}
	return tokenString, err
}

// ExtractClaims help to extract the JWT claims
func ExtractClaims(c *gin.Context) MapClaims {
	claims, exists := c.Get("JWT_PAYLOAD")
	if !exists {
		return make(MapClaims)
	}

	return claims.(MapClaims)
}

// ExtractClaimsFromToken help to extract the JWT claims from token
func ExtractClaimsFromToken(token *jwt.Token) MapClaims {
	if token == nil {
		return make(MapClaims)
	}

	claims := MapClaims{}
	for key, value := range token.Claims.(jwt.MapClaims) {
		claims[key] = value
	}

	return claims
}

// GetToken help to get the JWT token string
func GetToken(c *gin.Context) string {
	token, exists := c.Get("JWT_TOKEN")
	if !exists {
		return ""
	}

	return token.(string)
}
