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
	//"strconv"
	"strings"
	"time"
    "unicode"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type EncNegoClientParams struct {
	D1 string `json:"d1"`
	D2 string `json:"d2"`
	D3 string `json:"d3"`
	D4 string `json:"d4"`
	D5 int `json:"d5"`
}

type ClientInfo struct {
	Uuid   string
	PubKey *rsa.PublicKey
	SymKey []byte
}

var clientInfoMap map[string]ClientInfo
var clientInfo ClientInfo
var clientData map[string]interface{}
var aesCipher cipher.Block
var iv []byte

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
	if params.D5 >= 0 {
		//state, _ = strconv.Atoi(params.D5)
        state = params.D5
		fmt.Printf("request nego state %s %d\n", params.D5, state)
	}

    fmt.Printf("nego state %d\n", state)

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

		aClientInfo := ClientInfo{
            Uuid: id,
            SymKey: symKey,
            PubKey: pubKey,
        }
        fmt.Printf("add client info %s to map\n", id)
        clientInfoMap[id] = aClientInfo        

	case 1:
		clientInfo = clientInfoMap[id]
		c.BindJSON(&params)

        fmt.Printf("state 1, d2: %v\n", params.D2)
        fmt.Printf("client info %s, symkey size %d\n", clientInfo.Uuid, len(clientInfo.SymKey))
		aesCipher, err = aes.NewCipher(clientInfo.SymKey)
        if err != nil {
            fmt.Printf("failed creating cipher %s\n", err.Error())
            c.Abort()
            return
        }
		d2Arr := strings.Split(params.D2, "\\n")
		if len(d2Arr) < 2 {
			c.JSON(200, gin.H {
				"msg": "invalid data",
			})
			c.Abort()
			return
		}
		iv, err = base64.StdEncoding.DecodeString(d2Arr[0])
        if err != nil {
            fmt.Printf("error decoding iv %s\n", err.Error())
            c.Abort()
            return
        }
		decrypter := cipher.NewCBCDecrypter(aesCipher, iv)
		encryptedData, _ := base64.StdEncoding.DecodeString(d2Arr[1])
		data := make([]byte, len(encryptedData))
		decrypter.CryptBlocks(data, encryptedData)
        dataStr := string(data)
        fmt.Printf("clientData decrypted %v byte %v\n", dataStr, data)
        dataStrClean := strings.Map(func(r rune) rune {
            if unicode.IsGraphic(r) {
                return r
            }
            return -1
        }, dataStr)
		if err = json.Unmarshal([]byte(dataStrClean), &clientData); err != nil {
            fmt.Printf("unmarshal failed %s\n", err.Error())
            c.Abort()
            return
        }
	    fmt.Printf("clientData unmarshalled %v\n", clientData)
		//c.Set("data", dataJson)
		//c.Set("cipher", aesCipher)
		//c.Set("iv", iv)
		c.Next()
	}
}

func Api(c *gin.Context) {
	//var tmp interface{}
	//tmp, _ = c.Get("data")
	//data := tmp.(map[string]interface{})
	//tmp, _ = c.Get("cipher")
	//aesCipher := tmp.(cipher.Block)
	//tmp, _ = c.Get("iv")
	//iv := tmp.([]byte)

    fmt.Println("inside Api func")

	responseData := []byte("{\"data\": \"data rahasia balasan lho\"}")
	resDataEncrypted := make([]byte, len(responseData))

    aesCipher2, err := aes.NewCipher(clientInfo.SymKey)
    if err != nil {
        fmt.Printf("failed creating second cipher %s\n", err.Error())
        c.Abort()
        return
    }
    if iv == nil {
        fmt.Printf("iv is nil")
        c.Abort()
        return
    }
	encrypter := cipher.NewCBCEncrypter(aesCipher2, iv)
	encrypter.CryptBlocks(resDataEncrypted, responseData)
	resDataEncrypted64 := base64.StdEncoding.EncodeToString(resDataEncrypted)

	c.JSON(200, gin.H{
		"d2": resDataEncrypted64,
	})
}

func main() {
    clientInfoMap = make(map[string]ClientInfo)
	encNegoGateway := gin.Default()
	//encNegoGateway.GET("/", Home)
    apiGroup := encNegoGateway.Group("/api")
    apiGroup.Use(Negotiate)
	apiGroup.POST("/", Api)
	encNegoGateway.Static("/app", "../client")
	encNegoGateway.Run(":8080")
}
