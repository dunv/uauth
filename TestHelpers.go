package uauth

import (
	"fmt"
	"io"
	"log"
	"net/http"
)

// Only for testing
func DoRequestTest(req *http.Request) *http.Response {
	client := http.Client{}
	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	return res
}

// Only for testing
func JWTRequestTest(token string, method string, url string, payload io.Reader) *http.Request {
	req, err := http.NewRequest(method, url, payload)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	if err != nil {
		log.Fatal(err)
	}
	return req
}

// Only for testing
func JWTRequestGetTest(token string, method string, url string, payload io.Reader) *http.Request {
	req, err := http.NewRequest(method, fmt.Sprintf("%s?jwt=%s", url, token), payload)
	if err != nil {
		log.Fatal(err)
	}
	return req
}

// Only for testing
func AuthBasicRequestTest(user string, password string, method string, url string, payload io.Reader) *http.Request {
	req, err := http.NewRequest(method, url, payload)
	if err != nil {
		log.Fatal(err)
	}
	req.SetBasicAuth(user, password)
	return req
}
