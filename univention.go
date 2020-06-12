package itswizard_rest

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"github.com/itslearninggermany/itswizard_aes"
	"github.com/jinzhu/gorm"
	"io/ioutil"
	"net/http"
)

/*
Databasestructure for univention
*/
type UniventionUploads struct {
	gorm.Model
	UserID         uint
	OrganisationID uint
	InstitutionID  uint
	Filename       string
	Data           string `gorm:"type:MEDIUMTEXT"`
	Success        bool
}

type UniventionAes struct {
	gorm.Model
	UserID         uint `gorm:"unique"`
	OrganisationID uint
	InstitutionID  uint
	AesKey         []byte
}

type SendDataFromUniventionRequest struct {
	Filename string `json:"filename"`
	Content  string `json:"content"`
}

type SendAesKeyFromUniventionRequest struct {
	Username string `json:"username"`
	Key      []byte `json:"key"`
}

type SendDataFromUniventionResponse struct {
	Error   interface{} `json:"error"`
	Message struct {
		Data        string `json:"data"`
		Filename    string `json:"filename"`
		Information string `json:"information"`
	} `json:"message"`
}

const SendDataFromUnivnetionApi = "/univention/data"
const SendLogFromUnivnetionApi = "/univention/log"
const SendAesKeyFromUnivnetionApi = "/univention/aeskey"

/*
Send AES-Key to itslearning
*/
func (p *RestSession) SendAesKeyFromUnivention(username string) (string, []byte, error) {
	aes, err := itswizard_aes.NewAes()
	if err != nil {
		return "", []byte(""), err
	}
	o := SendAesKeyFromUniventionRequest{
		Username: username,
		Key:      aes.GetAesKey(),
	}
	b, err := json.Marshal(o)
	if err != nil {
		return "", []byte(""), err
	}
	req, err := http.NewRequest("POST", p.Endpoint+SendAesKeyFromUnivnetionApi, bytes.NewBuffer(b))
	if err != nil {
		return "", []byte(""), err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", p.Token)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		return "", []byte(""), err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", []byte(""), err
	}

	if string(body) == "Token is expired" {
		return string(body), []byte(""), errors.New(string(body))
	}
	if string(body) == "AESKey stored" {
		return string(body), aes.GetAesKey(), nil
	}
	if string(body) == "AESKey updated" {
		return string(body), aes.GetAesKey(), nil
	}

	return "", []byte(""), errors.New(string(body))
}

/*
Send JSON-Files with User and Groups
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
	req, err := http.NewRequest("POST", p.Endpoint+SendDataFromUnivnetionApi, bytes.NewBuffer(b))
	if err != nil {
		return sendData, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", p.Token)
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
Send Logfile from UCS-System
*/
func (p *RestSession) SendLogFromUnivention(data []byte) error {
	o := SendDataFromUniventionRequest{
		Filename: "logfile.txt",
		Content:  string(data),
	}

	b, err := json.Marshal(o)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", p.Endpoint+SendLogFromUnivnetionApi, bytes.NewBuffer(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", p.Token)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return err
	}

	if string(body) == "Token is expired" {
		return errors.New(string(body))
	}

	return err
}
