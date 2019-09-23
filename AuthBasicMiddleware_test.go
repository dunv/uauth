package uauth

import (
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dunv/uhttp"
)

func TestFailingAuthBasic(t *testing.T) {
	tmp := uhttp.Handler{
		AddMiddleware: AuthBasic("testUser", "fed3b61b26081849378080b34e693d2e"),
		GetHandler:    http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
	}
	ts := httptest.NewServer(tmp.HandlerFunc())
	defer ts.Close()
	res, err := http.Get(ts.URL)
	if err != nil {
		log.Fatal(err)
	}
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("did not prevent access to handler")
	}
}

func TestSuccessAuthBasic(t *testing.T) {
	tmp := uhttp.Handler{
		AddMiddleware: AuthBasic("testUser", "fed3b61b26081849378080b34e693d2e"),
		GetHandler:    http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
	}
	ts := httptest.NewServer(tmp.HandlerFunc())
	defer ts.Close()
	req, err := http.NewRequest(http.MethodGet, ts.URL, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.SetBasicAuth("testUser", "testPassword")
	client := http.Client{}
	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	if res.StatusCode == http.StatusUnauthorized {
		t.Errorf("did not allow access to handler")
	}
}
