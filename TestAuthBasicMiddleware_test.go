package uauth

import (
	"bufio"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dunv/uhttp"
	"github.com/dunv/ulog"
)

func authBasicFixture() http.HandlerFunc {
	// Suppress log-output
	ulog.SetWriter(bufio.NewWriter(nil), nil)

	return uhttp.NewHandler(
		uhttp.WithMiddlewares(AuthBasic("testUser", "fed3b61b26081849378080b34e693d2e")),
		uhttp.WithGet(func(r *http.Request, ret *int) interface{} { return nil }),
	).HandlerFunc(uhttp.NewUHTTP())
}

func TestFailingAuthBasic(t *testing.T) {
	ts := httptest.NewServer(authBasicFixture())
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
	ts := httptest.NewServer(authBasicFixture())
	defer ts.Close()
	req := AuthBasicRequestTest("testUser", "testPassword", http.MethodGet, ts.URL, nil)
	res := DoRequestTest(req)
	if res.StatusCode == http.StatusUnauthorized {
		t.Errorf("did not allow access to handler")
	}
}
