package adClient

import (
	"crypto/tls"
	"errors"
	"fmt"
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
func (lc *ADClient) GetAllUsers(BaseDN string) ([]map[string]string, error) {
	filter := fmt.Sprintf("(&(|(objectClass=user)(objectClass=person))(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(objectClass=computer))(!(objectClass=group)))")
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

func (lc *ADClient) GetUserInfo(username string) (map[string]string, error) {
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
		fmt.Sprintf(lc.UserFilter, username),
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
	user := map[string]string{}
	for _, attr := range lc.Attributes {
		user[attr] = sr.Entries[0].GetAttributeValue(attr)
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

	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(lc.UserFilter, username),
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
