package itswizard_rest

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"github.com/jinzhu/gorm"
	"github.com/segmentio/objconv/json"
	"io/ioutil"
	"net/http"
)

type Request struct {
	Endpoint 	string
	Key 		string
	Token 		string
}

type Response struct {
	Header string `json:"header"`
	Body string `json:"body"`
}

type Login struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Authorisation struct {
	gorm.Model
	Username string 		`json:"username"`
	Key string 				`json:"key"`
	Token string 			`json:"token"`
}


/*
func main () {
	fmt.Println(NewRequest("https://itswizard.de/rest/univention/setup/","user","password"))
}
*/

/*
Makes the data valid for the authentification
 */
func createLogin (username, password string) (string,error) {
	b, err := json.Marshal(Login{
		Username: username,
		Password: password,
	})
	if err != nil {
		return "",err
	}
	encoded := base64.StdEncoding.EncodeToString(b)
	return encoded,nil
}

/*
Get a new Request
 */
func NewRequest (endpoint,username, password string) (request *Request, response Response, err error){
	enc, err := createLogin(username,password)
	if err != nil {
		return nil, Response{}, err
	}
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer([]byte("")))
	req.Header.Set("Content-Type", "application/file")
	req.Header.Set("Authorization", enc)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		return nil, Response{}, err
	}
	defer resp.Body.Close()

	status := resp.Status
	header := fmt.Sprint(resp.Header)
	body, _ := ioutil.ReadAll(resp.Body)
	var auth Authorisation

	if err != nil {
		return nil, Response{
			Header: header,
			Body:   string(body),
		}, err
	}

	err = json.Unmarshal(body,&auth)
	if err != nil || status != "200 OK"{
		return nil, Response{
			Header: header,
			Body:   string(body),
		},err
	}

	request = new(Request)
	request.Key = auth.Key
	request.Token = auth.Token
	request.Endpoint = endpoint
	return request,Response{
		Header: header,
		Body:   string(body),
	},nil
}

