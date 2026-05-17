package main

import (
	"fmt"
	"log"
	"time"

	"github.com/skvdmt/jwt"
)

const secretKey = "super puper secret key"

func main() {
	// Создание токена.
	headers := jwt.Headers(
		jwt.Header("alg", "HS256"),
		jwt.Header("typ", "JWT"),
	)
	claims := jwt.Claims(
		jwt.Claim("nbf", time.Now().Format(time.RFC3339)),
		jwt.Claim("iat", time.Now().String()),
		jwt.Claim("exp", time.Now().Add(2*time.Minute).Format(time.RFC3339)),
	)
	token := jwt.NewToken(headers, claims, secretKey)
	fmt.Printf("token: %s\n", token)

	// Анализ токена.
	t, err := jwt.Parse(token)
	if err != nil {
		log.Fatal(err)
	}
	v, err := t.Valid(secretKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("token valid: %v\n", v)

	// Получение заголовка.
	a, ok := t.Header("alg")
	if ok {
		fmt.Printf("token header alg: %s, %v\n", a, ok)
	}

	// Получение клеймы.
	e, ok := t.Claim("exp")
	if ok {
		fmt.Printf("token claim exp: %s, %v\n", e, ok)
	}
}
