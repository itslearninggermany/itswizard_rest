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
	//	session.token = "pPAGRyh8B-UCi-m7D5QSevDeRrZsmXGY1bjKPGoOiPmH7ffxXXw_DedA62Zyu6oraaoTR79LdGQiQJS1IdNwvMA0xtWq5Y9jlgLLyTvzy25fdqzDqHnUlPi8kfVywMcesOQBrKArlHbqkt1RSEcXtqGC-jfG9In4Jzz0yeFKKZgDVN_DxLZWWa54u6F2Fy_Mkr6gpOQcSvJDtVU6fPXy2xS8RnnT6t_3wfxD0erG6NnGmxl118WfC-iCLRPFvJWPKbuCrSowfZP5m9edy7ggQ91mGC3RcY5Rnmdfqi0L5drNeq2hHJM6QoxNPuzcoWTlSpCVrEicVur8VlJla9-VHKP4xhWxHAS0i_0zqCIRnYBnDkIh25FAy3ieLUTZ3kh63kiqvAZHTOIPE-baUe1D54g6bMW8_kd9B0ZopvHaBzckijtL0rnBDdUpAMXLtzItgkxNzHCu2MvIAv1dQo8NT7NT81yi8nu-JOM6idxHIvzxjxtQsAQAyaUHYU_RQCaAlX7uRe_cE3A_EeYp-AtryjFzr9x6eqSi0_CnCU-hQwGjfFpHc3qaxzjYoMOABr6HiNVNSao9UZM28NCK2EakcTD52woQNcXg2tpDYGxMzpk3ZdOWLSP9VNs4CTukBPkwVmAY5MPZEwOrPts7vmlEsRbkaKv4apMv99IBDDHTZEH4BKqlCeBE_NgD52v-tVxao6xUxF9Jv5-cKQzP42pl9veQE9yCy5ahLvthMH9j_wEj6Gil0jnzvY4CWakD1HJKIbXonN7TsqD-NToSpP3POfyBy8Rhm5puVP___hsi6HOapbte81cC5acS1wm9Xho1RTEkYxnqLaES3OF6y1JYLxFhXZdE9APSrOtRYvHYVJAf42O-m0eN9n0FS-OH9vXZqLayjRCHqcCRm1i_eLpjozpHxz-QC1C_NctrBO0xYnww4dlsA1AX98qO_S1enb8Owo2A92K5BWHcI6es3Ul-Tk2kW_G2p8iHkYG5H05Ll3le7KysIrRzEYqgOJ3iFEcM5GuWxE93PDoRRvzbP-fSa_fcgi_upiGq5FXXoA2G7TG8v07WPzzKYXAUuhA9hIY="
	//	session.token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJBZG1pbiI6ZmFsc2UsIkF1dGhlbnRpY2F0ZWQiOnRydWUsIkVtYWlsIjoidGhvbWFzQG1mYXNmLmRlIiwiRmlyc3RBdXRoZW50aWNhdGlvbiI6dHJ1ZSwiRmlyc3RuYW1lIjoic3VwcG9ydCIsIklQIjoiMTcyLjMxLjE4LjE5MCIsIkluZm9ybWF0aW9uIjoiLS0iLCJJbnN0aXR1dGlvbiI6IlNjaHVsZW4gZGVyIExhbmRlc2hhdXB0c3RhZHQgRMO8c3NlbGRvcmYiLCJJbnN0aXR1dGlvbklEIjoyMywiTGFzdG5hbWUiOiIxMDAzNjUiLCJNb2JpbGUiOiI0OTE1MjI1NSIsIk9yZ2FuaXNhdGlvbklEIjoxMzIsIlNjaG9vbCI6IjEwMDM2NSBWb2xrZXIgUm9zaW4gU2NodWxlIiwiVHdvRmFjIjpmYWxzZSwiVXNlcklEIjoxMjgsIlVzZXJuYW1lIjoiMTAwMzY1IiwiZXhwIjoxNTg3NzMyMjQxLCJpYXQiOjE1ODc3Mjg2NDF9.VThUmV3KuUsjIioRaMB7KRBsAe7Hi5TvT2ykcxpNvrc"
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

	if string(body) == "Token is expired" {
		return user, errors.New(string(body))
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

	if string(body) == "Token is expired" {
		sendData.Error = errors.New(string(body))
	} else {
		err := json.Unmarshal(body, &sendData)
		if err != nil {
			return sendData, err
		}
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

/*
Return the person
*/
func (p *RestSession) TokenValid() (bool, error) {
	req, err := http.NewRequest("POST", p.endpoint+"/tokenValid", bytes.NewBuffer([]byte("")))
	if err != nil {
		return false, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", p.token)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	if string(body) == "Token is expired" {
		return false, errors.New(string(body))
	}
	if string(body) == "Token is valid" {
		return true, nil
	}
	return false, err
}
