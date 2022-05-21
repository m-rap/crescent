package main

import (
    "fmt"
    //"time"
    "github.com/gin-gonic/gin"
    "github.com/google/uuid"
)

type EncNegoParams struct {
    D1 string `json:"d1"`
    D2 string `json:"d2"`
    D3 string `json:"d3"`
    D4 string `json:"d4"`
}

func Home(c *gin.Context) {
    id, err := c.Cookie("uuid")

    if err != nil {
        fmt.Printf("id not exists: %s,%s\n", id, err)
        genId := uuid.New()
        id = genId.String()
        //c.SetCookie("uuid", id, 10 * 365 * 24 * 60 * 60, "/", "localhost", false, true)
    }

    var params EncNegoParams
    c.BindJSON(&params)
    //cliPubK := params.D1

    c.JSON(200, gin.H {
        "d1": "hello",
    })
}

func main() {
    encNegoGateway := gin.New()
    encNegoGateway.GET("/", Home)
    encNegoGateway.Run(":8080")
}
