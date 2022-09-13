package main

import (
	"encoding/json"
	"fmt"
	"log"

	adClient "github.com/saygik/go-ad-client"
)

func main() {
	client := &adClient.ADClient{
		Base:         "dc=dc,dc=local",
		Host:         "dc1.dc.local",
		Port:         389,
		UseSSL:       false,
		BindDN:       "CN=read-only-admin,DC=dc,DC=local",
		BindPassword: "read-only-admin",
		UserFilter:   "(userPrincipalName=%s)",
		GroupFilter:  "(memberUid=%s)",
		Attributes: []string{"userPrincipalName", "dn", "cn", "company", "department", "title", "telephoneNumber",
			"otherTelephone", "mobile", "mail", "pager", "msRTCSIP-PrimaryUserAddress", "url"},
	}
	defer client.Close()

	users, err := client.GetAllUsers()
	if err != nil {
		log.Fatalf("Error get user info user %s: %+v", "username", err)
	}
	jsonStringUsers, _ := json.Marshal(users)
	fmt.Println(string(jsonStringUsers))

}
