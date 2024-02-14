package adClient

import (
	"crypto/tls"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type ADClient struct {
	Attributes         []string
	Title              string
	Domain             string
	Base               string
	BindDN             string
	BindPassword       string
	GroupFilter        string // e.g. "(memberUid=%s)"
	Host               string
	ServerName         string
	UserFilter         string // e.g. "(userPrincipalName=%s)"
	ComputerFilter     string // e.g. "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
	Conn               *ldap.Conn
	Port               int
	InsecureSkipVerify bool
	UseSSL             bool
	SkipTLS            bool
	ClientCertificates []tls.Certificate // Adding client certificates
}

var arrayAttributes = map[string]bool{
	"memberOf":             true,
	"url":                  true,
	"proxyAddresses":       true,
	"servicePrincipalName": true,
	"otherTelephone":       true}

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
	//	filter := "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
	attr := []string{"name", "description", "cn", "operatingSystem", "operatingSystemVersion", "primaryGroupID", "servicePrincipalName",
		"distinguishedName", "userAccountControl", "lastLogonTimestamp", "extensionAttribute10"}
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
		lc.ComputerFilter,
		attr,
		nil,
	)

	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}
	users := make([]map[string]interface{}, 0)
	for index, entry := range sr.Entries {
		user := make(map[string]interface{})
		for _, attr := range entry.Attributes {
			if arrayAttributes[attr.Name] {
				if attr.Name == "servicePrincipalName" {
					user[attr.Name] = strings.Join(attr.Values, ",")
				}
				if attr.Name != "servicePrincipalName" {
					user[attr.Name] = attr.Values
				}
			} else {
				user[attr.Name] = attr.Values[0]
			}
		}
		if user["extensionAttribute10"] == "virtual" {
			user["virtual"] = true
		} else {
			user["virtual"] = false
		}
		stime := ""
		unixTimeStampString, ok := user["lastLogonTimestamp"].(string)
		if ok {
			unixTimeStamp, err := strconv.ParseInt(unixTimeStampString, 10, 64)
			if err == nil {
				unixTimeUTC := getTime(unixTimeStamp)
				//unixTimeUTC := time.Unix(unixTimeStamp, 0) //gives unix time stamp in utc
				stime = unixTimeUTC.Format(time.RFC3339)
			}
		}
		if len(stime) > 0 {
			user["lastLogonTime"] = stime
		}
		user["id"] = fmt.Sprintf("%s-%d", lc.Domain, index)
		user["domain"] = lc.Domain
		ouArr := strings.Split(user["distinguishedName"].(string), ",")
		user["ou"] = strings.Join(trimOU(reverseAndTrimFirst(ouArr[1:len(ouArr)-2])), " > ")
		users = append(users, user)
	}
	return users, nil
}
func reverseAndTrimFirst(s []string) []string {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}
func trimOU(s []string) []string {
	for i := 0; i < len(s); i++ {
		s[i] = s[i][3:]
	}
	return s
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

func getTime(input int64) time.Time {
	maxd := time.Duration(math.MaxInt64).Truncate(100 * time.Nanosecond)
	maxdUnits := int64(maxd / 100) // number of 100-ns units

	t := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
	for input > maxdUnits {
		t = t.Add(maxd)
		input -= maxdUnits
	}
	if input != 0 {
		t = t.Add(time.Duration(input * 100))
	}
	return t
}
