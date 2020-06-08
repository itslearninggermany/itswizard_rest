package itswizard_rest

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/itslearninggermany/itswizard_handlingerrors"
	"github.com/jinzhu/gorm"
	"github.com/segmentio/objconv/json"
	"io/ioutil"
	"net/http"
	"strconv"
)

type Request struct {
	Endpoint string
	Key      string
	Token    string
}

type Response struct {
	Status  string      `json:"status"`
	Error   error       `json:"error"`
	Message interface{} `json:"message"`
}

type AuthentificationResponse struct {
	Status  string      `json:"status"`
	Error   interface{} `json:"error"`
	Message struct {
		Jwt string `json:"jwt"`
	} `json:"message"`
}

type MeResponse struct {
	Status  string      `json:"status"`
	Error   interface{} `json:"error"`
	Message struct {
		Username            string `json:"Username"`
		UserID              int    `json:"UserID"`
		FirstAuthentication bool   `json:"FirstAuthentication"`
		Authenticated       bool   `json:"Authenticated"`
		TwoFac              bool   `json:"TwoFac"`
		Firstname           string `json:"Firstname"`
		Lastname            string `json:"Lastname"`
		Mobile              string `json:"Mobile"`
		IPAddress           string `json:"IpAddress"`
		Institution         string `json:"Institution"`
		School              string `json:"School"`
		Email               string `json:"Email"`
		Information         string `json:"Information"`
		Admin               bool   `json:"Admin"`
		OrganisationID      int    `json:"OrganisationID"`
		InstitutionID       int    `json:"InstitutionID"`
	} `json:"message"`
}

type User struct {
	Username    string
	UserID      int
	Firstname   string
	Lastname    string
	Mobile      string
	Institution string
	School      string
	Email       string
}

type JWT struct {
	JWT string `json:"jwt"`
}

type ErrorBody struct {
	error string `json:"error"`
}

type Login struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RestSession struct {
	endpoint string
	token    string
}

type SendDataFromUniventionRequest struct {
	Filename string `json:"filename"`
	Content  string `json:"content"`
}

type SendDataFromUniventionResponse struct {
	Error   interface{} `json:"error"`
	Message struct {
		Data        string `json:"data"`
		Filename    string `json:"filename"`
		Information string `json:"information"`
	} `json:"message"`
}

/*
Makes the data valid for the authentification
*/
func CreateLogin(username, password string) (string, error) {
	b, err := json.Marshal(Login{
		Username: username,
		Password: password,
	})
	if err != nil {
		return "", err
	}
	encoded := base64.StdEncoding.EncodeToString(b)
	return encoded, nil
}

/*
Decode a Login
*/
func DecodeLogin(encoded string) (login Login, err error) {
	erg, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return login, err
	}
	err = json.Unmarshal(erg, &login)
	if err != nil {
		return login, err
	}
	return login, nil
}

/*
Get a new Request
*/
func NewSession(endpoint, username, password string) (session RestSession, err error) {
	enc, err := CreateLogin(username, password)
	if err != nil {
		return session, err
	}

	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer([]byte("")))
	if err != nil {
		return session, err
	}
	req.Header.Set("Content-Type", "application/file")
	req.Header.Set("Authorization", enc)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		return session, err
	}

	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	status := resp.Status

	if status != "200 OK" {
		if err != nil {
			return session, errors.New("Status: " + status + "Header: " + fmt.Sprint(resp.Header) + "Body: " + string(body))
		}
	}

	var responseStruct AuthentificationResponse
	err = json.Unmarshal(body, &responseStruct)
	if err != nil {
		return session, errors.New("Error: " + err.Error() + "Status: " + status + "Header: " + fmt.Sprint(resp.Header) + "Body: " + string(body))
	}

	session.token = responseStruct.Message.Jwt
	session.endpoint = endpoint
	return session, nil
}

/*
Return the person
*/
func (p *RestSession) Me() (user User, err error) {
	req, err := http.NewRequest("POST", p.endpoint+"/me", bytes.NewBuffer([]byte("")))
	if err != nil {
		return user, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", p.token)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		return user, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return user, err
	}

	var meResponse MeResponse
	err = json.Unmarshal(body, &meResponse)
	if err != nil {
		return user, err
	}

	user = User{
		Username:    meResponse.Message.Username,
		UserID:      meResponse.Message.UserID,
		Firstname:   meResponse.Message.Firstname,
		Lastname:    meResponse.Message.Lastname,
		Mobile:      meResponse.Message.Mobile,
		Institution: meResponse.Message.Institution,
		School:      meResponse.Message.School,
		Email:       meResponse.Message.Email,
	}

	return user, err
}

/*
API for univention
*/
func (p *RestSession) SendDataFromUnivention(filename string, data []byte) (sendData SendDataFromUniventionResponse, err error) {
	o := SendDataFromUniventionRequest{
		Filename: filename,
		Content:  string(data),
	}

	b, err := json.Marshal(o)
	if err != nil {
		return sendData, err
	}

	req, err := http.NewRequest("POST", p.endpoint+"/univention", bytes.NewBuffer(b))
	if err != nil {
		return sendData, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", p.token)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		return sendData, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return sendData, err
	}

	err = json.Unmarshal(body, &sendData)
	if err != nil {
		return sendData, err
	}

	return sendData, err
}

/*
Sets a status Code and an Error JSON in the body
*/
func ResponseError(statusNumber int, err error, w http.ResponseWriter, userName string, dbWebserver *gorm.DB) {
	w.WriteHeader(statusNumber)
	b, err := json.Marshal(Response{
		Status: strconv.Itoa(statusNumber),
		Error:  err,
	})
	if err != nil {
		itswizard_handlingerrors.WritingToErrorLog(dbWebserver, userName, err.Error())
		return
	}
	_, err = fmt.Fprint(w, string(b))
	if err != nil {
		itswizard_handlingerrors.WritingToErrorLog(dbWebserver, userName, err.Error())
		return
	}
}

func ResponseError500(w http.ResponseWriter, userName string, dbWebserver *gorm.DB, err error) {
	ResponseError(500, errors.New("Internal Server Error"), w, userName, dbWebserver)
	itswizard_handlingerrors.WritingToErrorLog(dbWebserver, userName, err.Error())
}
