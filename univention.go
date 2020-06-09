package itswizard_rest

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
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
