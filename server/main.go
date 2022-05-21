package main

import (
	"crypto/aes"
	"crypto/cipher"
	cRand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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

		fmt.Printf("d1 %s\n", params.D1)

		//pubKeyDER, _ := base64.StdEncoding.DecodeString(params.D1)
		//pubKeyInterface, err := x509.ParsePKIXPublicKey(pubKeyDER)
		//if err != nil {
		//	fmt.Printf("error parse public key: %s\n", err.Error())
		//	c.Abort()
		//	return
		//}
		//pubKey, ok := pubKeyInterface.(*rsa.PublicKey)
		//if !ok {
		//	fmt.Printf("can't cast pubkey\n")
		//}

		pubKeyPem, _ := base64.StdEncoding.DecodeString(params.D1)
		pubKeyPemBlock, _ := pem.Decode(pubKeyPem)
		if pubKeyPemBlock == nil {
			fmt.Printf("can't find pem block.\n")
			c.Abort()
			return
		}
		fmt.Printf("pem block: %v\n", pubKeyPemBlock)
		pubKey, err := x509.ParsePKCS1PublicKey(pubKeyPemBlock.Bytes)
		if err != nil {
			fmt.Printf("failed parse pem block: %s\n", err.Error())
			c.Abort()
			return
		}

		id = uuid.NewString()
		symKey := make([]byte, 32)
		rand.Seed(time.Now().Unix())
		rand.Read(symKey)
		encryptedSymKey, _ := rsa.EncryptOAEP(sha256.New(), cRand.Reader, pubKey, symKey, nil)
		encryptedSymKeyB64 := base64.StdEncoding.EncodeToString(encryptedSymKey)

		c.SetCookie("uuid", id, 10*365*24*60*60, "/", "localhost", false, true)
		c.JSON(200, gin.H{
			"d4": encryptedSymKeyB64,
		})

	case 1:
		clientInfo := clientInfoMap[id]
		c.BindJSON(&params)
		aesCipher, _ := aes.NewCipher(clientInfo.SymKey)
		encryptedData, _ := base64.StdEncoding.DecodeString(params.D2)
		data := make([]byte, len(encryptedData))
		aesCipher.Decrypt(data, encryptedData)
		var dataJson map[string]interface{}
		json.Unmarshal(data, &dataJson)
		c.Set("data", dataJson)
		c.Set("cipher", aesCipher)
		c.Next()
	}
}

func Api(c *gin.Context) {
	var tmp interface{}
	tmp, _ = c.Get("data")
	data := tmp.(map[string]interface{})
	tmp, _ = c.Get("cipher")
	cipher := tmp.(cipher.Block)
	fmt.Println(data)

	responseData := []byte("{data: data rahasia balasan lho}")
	resDataEncrypted := make([]byte, len(responseData))
	cipher.Encrypt(resDataEncrypted, responseData)
	resDataEncrypted64 := base64.StdEncoding.EncodeToString(resDataEncrypted)

	c.JSON(200, gin.H{
		"d2": resDataEncrypted64,
	})
}

func main() {
	encNegoGateway := gin.New()
	//encNegoGateway.GET("/", Home)
	encNegoGateway.POST("/api", Negotiate, Api)
	encNegoGateway.Static("/app", "../client")
	encNegoGateway.Run(":8080")
}
