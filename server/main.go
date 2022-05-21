package main

import (
	"crypto/aes"
	cRand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type EncNegoClientParams struct {
	D1 string `json:"d1"`
	D2 string `json:"d2"`
}

type ClientInfo struct {
	Uuid   string
	PubKey *rsa.PublicKey
	SymKey []byte
}

var clientInfoMap map[string]ClientInfo

func Home(c *gin.Context) {
	c.String(200, "hello")
}

func Negotiate(c *gin.Context) {
	state := 0
	var params EncNegoClientParams

	id, err := c.Cookie("uuid")

	if err != nil {
		fmt.Printf("id not exists: %s:%T,%s:%T\n", id, id, err, err)
	} else {
		state = 1
	}

	switch state {
	case 0:
		c.BindJSON(&params)
		if strings.Trim(params.D1, " ") == "" {
			c.JSON(200, gin.H{
				"msg": "invalid params",
			})
			return
		}

		pubKeyDER, _ := base64.StdEncoding.DecodeString(params.D1)
		pubKeyInterface, _ := x509.ParsePKIXPublicKey(pubKeyDER)
		pubKey, _ := pubKeyInterface.(*rsa.PublicKey)
		id = uuid.NewString()
		symKey := make([]byte, 32)
		rand.Seed(time.Now().Unix())
		rand.Read(symKey)
		encryptedSymKey, _ := rsa.EncryptOAEP(sha256.New(), cRand.Reader, pubKey, symKey, nil)
		encryptedSymKeyB64 := base64.StdEncoding.EncodeToString(encryptedSymKey)

		c.SetCookie("uuid", id, 10*365*24*60*60, "/", "localhost", false, true)
		c.JSON(200, gin.H{
			"d1": encryptedSymKeyB64,
		})

	case 1:
		clientInfo := clientInfoMap[id]
		c.BindJSON(&params)
		aesCipher, _ := aes.NewCipher(clientInfo.SymKey)
		encryptedData, _ := base64.StdEncoding.DecodeString(params.D2)
		data := make([]byte, len(encryptedData))
		aesCipher.Decrypt(encryptedData, data)
		var dataJson map[string]interface{}
		json.Unmarshal(data, &dataJson)
		c.Set("data", dataJson)
		c.Next()
	}
}

func Api(c *gin.Context) {
	dataInterface, _ := c.Get("data")
	data := dataInterface.(map[string]interface{})
	fmt.Println(data)
	c.JSON(200, gin.H{
		"msg": "data received",
	})
}

func main() {
	encNegoGateway := gin.New()
	encNegoGateway.GET("/", Home)
	encNegoGateway.GET("/api", Negotiate, Api)
	encNegoGateway.Run(":8080")
}
