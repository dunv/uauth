package uauth

import (
	"bufio"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dunv/uauth/helpers"
	"github.com/dunv/uhttp"
	"github.com/dunv/ulog"
)

func authBasicFixture() uhttp.Handler {
	// Suppress log-output
	ulog.SetWriter(bufio.NewWriter(nil), nil)

	return uhttp.Handler{
		AddMiddleware: AuthBasic("testUser", "fed3b61b26081849378080b34e693d2e"),
		GetHandler:    http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
	}
}

func TestFailingAuthBasic(t *testing.T) {
	ts := httptest.NewServer(authBasicFixture().HandlerFunc())
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
	ts := httptest.NewServer(authBasicFixture().HandlerFunc())
	defer ts.Close()
	req := helpers.AuthBasicRequestTest("testUser", "testPassword", http.MethodGet, ts.URL, nil)
	res := helpers.DoRequestTest(req)
	if res.StatusCode == http.StatusUnauthorized {
		t.Errorf("did not allow access to handler")
	}
}
