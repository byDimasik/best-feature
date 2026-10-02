package main

import (
	"fmt"
	"log"
	"time"

	"github.com/byDimasik/best-feature/jwt"
)

func main() {
	now := time.Now().Unix()

	token, err := jwt.Encode("user-123", now, now+3600, map[string]interface{}{
		"role":  "admin",
		"email": "user@example.com",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("token:", token)

	decoded, err := jwt.Decode(token)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("decoded: %+v\n", decoded)
}
