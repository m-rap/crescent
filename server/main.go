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
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type EncNegoClientParams struct {
	D1 string `json:"d1"`
	D2 string `json:"d2"`
	D3 string `json:"d3"`
	D4 string `json:"d4"`
	D5 string `json:"d5"`
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

	//raw, _ := c.GetRawData()
	//fmt.Printf("request %v\n", string(raw))

	var params EncNegoClientParams
	c.ShouldBindJSON(&params)

	id, err := c.Cookie("uuid")

	if err != nil {
		fmt.Printf("id not exists: %s:%T,%s:%T\n", id, id, err, err)
	} else {
		//state = 1
	}

	fmt.Printf("params d5 %s\n", params.D5)
	if params.D5 != "" {
		state, _ = strconv.Atoi(params.D5)
		fmt.Printf("request nego state %s %d\n", params.D5, state)
	}

	switch state {
	case 0:
		if strings.Trim(params.D1, " ") == "" {
			c.JSON(200, gin.H{
				"msg": "invalid params",
			})
			return
		}

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

		//pubKeyPem, _ := base64.StdEncoding.DecodeString(params.D1)
		pubKeyPemBlock, _ := pem.Decode([]byte(params.D1))
		if pubKeyPemBlock == nil {
			fmt.Printf("can't find pem block.\n")
			c.Abort()
			return
		}
		fmt.Printf("pem block: %v\n", pubKeyPemBlock)
		pubKeyInterface, err := x509.ParsePKIXPublicKey(pubKeyPemBlock.Bytes)
		pubKey, _ := pubKeyInterface.(*rsa.PublicKey)
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

		fmt.Println("set cookie")
		c.SetCookie("uuid", id, 10*365*24*60*60, "/", "localhost", false, true)
		fmt.Println("write response in json")
		c.JSON(200, gin.H{
			"d4": encryptedSymKeyB64,
		})
		fmt.Println("abort because still state 0")
		c.Abort()

	case 1:
		clientInfo := clientInfoMap[id]
		c.BindJSON(&params)
		aesCipher, _ := aes.NewCipher(clientInfo.SymKey)
		d2Arr := strings.Split(params.D2, "\n")
		if len(d2Arr) < 2 {
			c.JSON(200, gin.H {
				"msg": "invalid data"
			})
			c.Abort()
			return
		}
		iv, _ := base64.StdEncoding.DecodeString(d2Arr[0])
		decrypter := cipher.NewCBCDecrypter(aesCipher, iv)
		encryptedData, _ := base64.StdEncoding.DecodeString(d2Arr[1])
		data := make([]byte, len(encryptedData))
		decrypter.Decrypt(data, encryptedData)
		var dataJson map[string]interface{}
		json.Unmarshal(data, &dataJson)
		c.Set("data", dataJson)
		c.Set("cipher", aesCipher)
		c.set("iv", iv)
		c.Next()
	}
}

func Api(c *gin.Context) {
	var tmp interface{}
	tmp, _ = c.Get("data")
	data := tmp.(map[string]interface{})
	tmp, _ = c.Get("cipher")
	aesCipher := tmp.(cipher.Block)
	tmp, _ = c.Get("iv")
	iv := tmp.(string)
	fmt.Println(data)

	responseData := []byte("{data: data rahasia balasan lho}")
	resDataEncrypted := make([]byte, len(responseData))
	encrypter := cipher.NewCBCEncrypter(aesCipher, iv)
	encrypter.Encrypt(resDataEncrypted, responseData)
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
