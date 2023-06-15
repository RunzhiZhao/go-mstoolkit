# jwt
基于github.com/golang-jwt/jwt/v5二次封装的的jwt工具包

## Usage
```go
package main

import (
    "fmt"
    "time"

    "github.com/RunzhiZhao/go-mstoolkit/jwt"
)

func main() {
    // generate token
    privateKey := []byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIOF17froyQplFvkuHWfd8w+TDvZJaqa8Vb+8EYCXn1PJ
-----END PRIVATE KEY-----`)
    tokenGenerator, err := jwt.NewTokenGenerator(jwt.SigningMethodEdDSA, privateKey,WithExpires(time.Hour))
    if err != nil {
        panic(err)
    }
    tokenStr, err := tokenGenerator.Generate(jwt.TokenInfo{UserID: 1, RoleID: 1})
    if err != nil {
        panic(err)
    }

    // verify token
    publicKey := []byte(`-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAjc7me3Kg+7KKVu+gri+xeN8CThJx/CwP7LnR5Ul5K9A=
-----END PUBLIC KEY-----`)
    tokenVerifier, err := jwt.NewTokenVerifier(jwt.SigningMethodEdDSA, publicKey)
    if err != nil {
        panic(err)
    }
    tokenInfo, err := tokenVerifier.Verify(tokenStr)
    if err != nil {
        panic(err)
    }
    fmt.Println(tokenInfo.UserID, tokenInfo.RoleID)
}

```
