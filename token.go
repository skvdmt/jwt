// Package jwt simple JSON WEB TOKEN to create and validate tokens
package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Token Структора JWT токена.
type Token struct {
	headers   *Params
	claims    *Params
	signature string
	key       string
}

// NewToken Конструктор JWT токена.
func NewToken(headers, claims *Params, key string) string {
	t := &Token{
		headers: headers,
		claims:  claims,
		key:     key,
	}
	return t.encode()
}

// Parse Парсинг JWT токена.
func Parse(token string) (*Token, error) {
	p := strings.Split(token, ".")
	if len(p) != 3 {
		return nil, fmt.Errorf("unknown token format token")
	}
	// Декодирование заголовков.
	h, err := decodeParams(p[0])
	if err != nil {
		return nil, err
	}
	// Декодирование клейм.
	c, err := decodeParams(p[1])
	if err != nil {
		return nil, err
	}
	return &Token{
		headers:   h,
		claims:    c,
		signature: p[2],
	}, nil
}

// Valid Проверка валидности токена.
func (t *Token) Valid(key string) (valid bool, cause error) {
	// Проверка подписи.
	_, _, s := t.encodeParts(key)
	if s != t.signature {
		return false, fmt.Errorf("bad signature")
	}
	// Проверка начала срока действительности токена.
	n, ok := (*t.claims)["nbf"]
	if !ok {
		return false, fmt.Errorf("nbf claim not found")
	}
	nt, err := time.Parse(time.RFC3339, n)
	if err != nil {
		return false, fmt.Errorf("bad nbf claim: %v", err)
	}
	if nt.Unix() > time.Now().Unix() {
		return false, fmt.Errorf("token not yet valid")
	}
	// Проверка окончания срока действительности токена.
	e, ok := (*t.claims)["exp"]
	if !ok {
		return false, fmt.Errorf("exp claim not found")
	}
	et, err := time.Parse(time.RFC3339, e)
	if err != nil {
		return false, fmt.Errorf("bad exp claim")
	}
	if et.Unix() < time.Now().Unix() {
		return false, fmt.Errorf("token expired")
	}
	return true, nil
}

// encode Кодирование хеша токена.
func (t *Token) encode() string {
	h, c, s := t.encodeParts(t.key)
	return fmt.Sprintf("%s.%s.%s", h, c, s)
}

// encodeParts Кодировние токена частями.
func (t *Token) encodeParts(key string) (headers string, claims string, signature string) {
	// Создание хеша заголовков.
	j, _ := json.Marshal(t.headers)
	h := base64.RawURLEncoding.EncodeToString(j)
	// Создание хеша клейм.
	j, _ = json.Marshal(t.claims)
	c := base64.RawURLEncoding.EncodeToString(j)
	// Создание хеша токена.
	hasher := hmac.New(sha256.New, []byte(key))
	fmt.Fprintf(hasher, "%s.%s", h, c)
	s := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))
	return h, c, s
}

// decodeParams Декодирование параметров.
func decodeParams(s string) (*Params, error) {
	d, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	p := make(Params)
	if err := json.Unmarshal(d, &p); err != nil {
		return nil, err
	}
	return &p, nil
}
