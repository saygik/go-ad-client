package adClient

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

type ADClient struct {
	Attributes         []string
	Base               string
	BindDN             string
	BindPassword       string
	GroupFilter        string // e.g. "(memberUid=%s)"
	Host               string
	ServerName         string
	UserFilter         string // e.g. "(userPrincipalName=%s)"
	Conn               *ldap.Conn
	Port               int
	InsecureSkipVerify bool
	UseSSL             bool
	SkipTLS            bool
	ClientCertificates []tls.Certificate // Adding client certificates
}

var arrayAttributes = map[string]bool{
	"memberOf":       true,
	"url":            true,
	"proxyAddresses": true,
	"otherTelephone": true}

func (lc *ADClient) Connect() error {
	isClosing := true
	if lc.Conn != nil {
		isClosing = lc.Conn.IsClosing()
	}
	if lc.Conn == nil || isClosing {
		var l *ldap.Conn
		var err error
		address := fmt.Sprintf("%s:%d", lc.Host, lc.Port)
		if !lc.UseSSL {
			l, err = ldap.Dial("tcp", address)
			if err != nil {
				return err
			}

			// Reconnect with TLS
			if !lc.SkipTLS {
				err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
				if err != nil {
					return err
				}
			}
		} else {
			config := &tls.Config{
				InsecureSkipVerify: lc.InsecureSkipVerify,
				ServerName:         lc.ServerName,
			}
			if lc.ClientCertificates != nil && len(lc.ClientCertificates) > 0 {
				config.Certificates = lc.ClientCertificates
			}
			l, err = ldap.DialTLS("tcp", address, config)
			if err != nil {
				return err
			}
		}

		lc.Conn = l
	}
	return nil
}
func (lc *ADClient) Close() {
	if lc.Conn != nil {
		lc.Conn.Close()
		lc.Conn = nil
	}
}
func (lc *ADClient) Bind() error {
	if lc.BindDN != "" && lc.BindPassword != "" {
		err := lc.Conn.Bind(lc.BindDN, lc.BindPassword)
		if err != nil {
			return err
		}
		return nil
	}
	return nil
}
func (lc *ADClient) GetAllUsersWithFilter(BaseDN string, filter string) ([]map[string]string, error) {
	if filter == "" {
		filter = fmt.Sprintf("(&(|(objectClass=user)(objectClass=person))(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(objectClass=computer))(!(objectClass=group)))")
	}
	err := lc.Connect()
	if err != nil {
		return nil, err
	}
	err = lc.Bind()
	if err != nil {
		return nil, err
	}
	searchRequest := ldap.NewSearchRequest(
		BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		lc.Attributes,
		nil,
	)
	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}
	users := make([]map[string]string, 0)
	for _, entry := range sr.Entries {
		user := make(map[string]string)
		for _, attr := range entry.Attributes {
			user[attr.Name] = attr.Values[0]
		}
		users = append(users, user)
	}
	return users, nil
}
func (lc *ADClient) GetAllUsers() ([]map[string]interface{}, error) {
	//	filter := fmt.Sprintf("(&(|(objectClass=user)(objectClass=person))(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(objectClass=computer))(!(objectClass=group)))")
	err := lc.Connect()
	if err != nil {
		return nil, err
	}
	err = lc.Bind()
	if err != nil {
		return nil, err
	}
	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		lc.UserFilter,
		lc.Attributes,
		nil,
	)

	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}
	users := make([]map[string]interface{}, 0)
	for _, entry := range sr.Entries {
		user := make(map[string]interface{})
		for _, attr := range entry.Attributes {
			if arrayAttributes[attr.Name] {
				if attr.Name == "memberOf" {
					user[attr.Name] = firstMembersOfCommaStrings(attr.Values)
				} else {
					user[attr.Name] = attr.Values
				}
			} else {
				user[attr.Name] = attr.Values[0]
			}
		}
		users = append(users, user)
	}
	return users, nil
}
func (lc *ADClient) GetAllComputers() ([]map[string]interface{}, error) {
	filter := fmt.Sprintf("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))")
	attr := []string{"name", "objectSid", "cn", "operatingSystem", "operatingSystemVersion", "primaryGroupID", "servicePrincipalName",
		"distinguishedName", "userAccountControl", "lastLogon"}
	err := lc.Connect()
	if err != nil {
		return nil, err
	}
	err = lc.Bind()
	if err != nil {
		return nil, err
	}
	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		attr,
		nil,
	)

	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}
	users := make([]map[string]interface{}, 0)
	for _, entry := range sr.Entries {
		user := make(map[string]interface{})
		for _, attr := range entry.Attributes {
			if arrayAttributes[attr.Name] {
				if attr.Name == "memberOf" {
					user[attr.Name] = firstMembersOfCommaStrings(attr.Values)
				} else {
					user[attr.Name] = attr.Values
				}
			} else {
				user[attr.Name] = attr.Values[0]
			}
		}
		users = append(users, user)
	}
	return users, nil
}
func firstMembersOfCommaStrings(commaStrings []string) []string {
	var str []string
	output := make([]string, 0)
	for _, commaString := range commaStrings {
		str = strings.Split(commaString, ",")
		if len(str) > 0 {
			output = append(output, str[0][3:])
		} else {
			output = append(output, commaString)
		}
	}
	return output
}
func (lc *ADClient) GetGroupUsers(group string) ([]map[string]interface{}, error) {
	filter := fmt.Sprintf(lc.GroupFilter, group)
	err := lc.Connect()
	if err != nil {
		return nil, err
	}
	err = lc.Bind()
	if err != nil {
		return nil, err
	}
	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		lc.Attributes,
		nil,
	)
	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}
	users := make([]map[string]interface{}, 0)
	for _, entry := range sr.Entries {
		user := make(map[string]interface{})
		for _, attr := range entry.Attributes {
			if arrayAttributes[attr.Name] {
				user[attr.Name] = attr.Values
			} else {
				user[attr.Name] = attr.Values[0]
			}
		}
		users = append(users, user)
	}
	return users, nil
}

func (lc *ADClient) GetUserInfo(username string) (map[string]interface{}, error) {
	err := lc.Connect()
	if err != nil {
		return nil, err
	}
	err = lc.Bind()
	if err != nil {
		return nil, err
	}
	//	attributes := append(lc.Attributes, "dn")
	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(userPrincipalName=%s)", username),
		lc.Attributes,
		nil,
	)

	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}
	if len(sr.Entries) < 1 {
		return nil, errors.New("User does not exist")
	}

	if len(sr.Entries) > 1 {
		return nil, errors.New("Too many entries returned")
	}
	user := make(map[string]interface{})
	//for _, attr := range lc.Attributes {
	//	user[attr] = sr.Entries[0].GetAttributeValue(attr)
	//}
	for _, entry := range sr.Entries {
		for _, attr := range entry.Attributes {
			if arrayAttributes[attr.Name] {
				if attr.Name == "memberOf" {
					user[attr.Name] = firstMembersOfCommaStrings(attr.Values)
				} else {
					user[attr.Name] = attr.Values
				}
			} else {
				user[attr.Name] = attr.Values[0]
			}
		}
	}
	return user, nil
}
func (lc *ADClient) Authenticate(username, password string) (bool, map[string]string, error) {
	err := lc.Connect()
	if err != nil {
		return false, nil, err
	}

	// First bind with a read only user
	if lc.BindDN != "" && lc.BindPassword != "" {
		err := lc.Conn.Bind(lc.BindDN, lc.BindPassword)
		if err != nil {
			return false, nil, err
		}
	}
	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(userPrincipalName=%s)", username),
		lc.Attributes,
		nil,
	)

	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return false, nil, err
	}

	if len(sr.Entries) < 1 {
		return false, nil, errors.New("User does not exist")
	}

	if len(sr.Entries) > 1 {
		return false, nil, errors.New("Too many entries returned")
	}

	userDN := sr.Entries[0].DN
	user := map[string]string{}
	for _, attr := range lc.Attributes {
		user[attr] = sr.Entries[0].GetAttributeValue(attr)
	}

	// Bind as the user to verify their password
	err = lc.Conn.Bind(userDN, password)
	if err != nil {
		return false, user, errors.New("Invalid password")
	}

	// Rebind as the read only user for any further queries
	if lc.BindDN != "" && lc.BindPassword != "" {
		err = lc.Conn.Bind(lc.BindDN, lc.BindPassword)
		if err != nil {
			return true, user, err
		}
	}

	return true, user, nil
}
