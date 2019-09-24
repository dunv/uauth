package uauth

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/dunv/uauth/helpers"
	"github.com/dunv/uhttp"
)

type testUserModel struct {
	jwt.StandardClaims
	GivenName string   `json:"GivenName"`
	Surname   string   `json:"Surname"`
	Role      []string `json:"Role"`
}

type authHybridResponseModel struct {
	JWTUser        *testUserModel `json:"jwtUser"`
	BasicUser      string         `json:"basicUser"`
	IsAuthBasic    bool           `json:"isAuthBasic"`
	IsAuthJWT      bool           `json:"isAuthJWT"`
	IsAuth_jwt1    bool           `json:"isAuth_jwt1"`
	IsAuth_jwt2    bool           `json:"isAuth_jwt2"`
	IsAuth_jwt1Get bool           `json:"isAuth_jwt1Get"`
	IsAuth_jwt2Get bool           `json:"isAuth_jwt2Get"`
}

func authHybridTestFixture() uhttp.Handler {
	return uhttp.Handler{
		AddMiddleware: AuthHybrid(
			map[string]string{
				"jwt1": "qwertyuiopasdfghjklzxcvbnm123456",
				"jwt2": "1234qwertyuiopasdfghjklzxcvbnm123456",
			},
			"testUser",
			"fed3b61b26081849378080b34e693d2e",
			testUserModel{},
		),
		GetHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if testUser, ok := CustomUser(r).(*testUserModel); ok {
				uhttp.Render(w, r, authHybridResponseModel{
					JWTUser:        testUser,
					IsAuthBasic:    IsAuthBasic(r),
					IsAuthJWT:      IsAuthJWT(r),
					IsAuth_jwt1:    IsAuthMethod("jwt1", r),
					IsAuth_jwt2:    IsAuthMethod("jwt2", r),
					IsAuth_jwt1Get: IsAuthMethod("jwt1Get", r),
					IsAuth_jwt2Get: IsAuthMethod("jwt2Get", r),
				})
			} else if testUser, ok := CustomUser(r).(string); ok {
				uhttp.Render(w, r, authHybridResponseModel{
					BasicUser:      testUser,
					IsAuthBasic:    IsAuthBasic(r),
					IsAuthJWT:      IsAuthJWT(r),
					IsAuth_jwt1:    IsAuthMethod("jwt1", r),
					IsAuth_jwt2:    IsAuthMethod("jwt2", r),
					IsAuth_jwt1Get: IsAuthMethod("jwt1Get", r),
					IsAuth_jwt2Get: IsAuthMethod("jwt2Get", r),
				})
			}
		}),
	}
}

func checkAuthHybridResponse(res *http.Response, expected *authHybridResponseModel, t *testing.T) {
	if expected != nil {
		parsed := authHybridResponseModel{}
		if err := json.NewDecoder(res.Body).Decode(&parsed); err != nil {
			t.Errorf("could not parse response model %v", err)
			return
		}

		if parsed.IsAuthBasic != expected.IsAuthBasic {
			t.Errorf("isAuthBasic does not match")
			return
		}
		if parsed.IsAuthJWT != expected.IsAuthJWT {
			t.Errorf("isAuthJWT does not match")
			return
		}
		if parsed.IsAuth_jwt1 != expected.IsAuth_jwt1 {
			t.Errorf("isAuth_jwt1 does not match")
			return
		}
		if parsed.IsAuth_jwt2 != expected.IsAuth_jwt2 {
			t.Errorf("isAuth_jwt2 does not match")
			return
		}
		if parsed.IsAuth_jwt1Get != expected.IsAuth_jwt1Get {
			t.Errorf("isAuth_jwt1Get does not match")
			return
		}
		if parsed.IsAuth_jwt2Get != expected.IsAuth_jwt2Get {
			t.Errorf("isAuth_jwt2Get does not match")
			return
		}
		if parsed.BasicUser != expected.BasicUser {
			t.Errorf("basicUser does not match")
			return
		}

		if expected.JWTUser != nil {
			if parsed.JWTUser == nil {
				t.Errorf("jwtUser does not match")
				return
			}
			if (*parsed.JWTUser).GivenName != (*expected.JWTUser).GivenName ||
				(*parsed.JWTUser).Surname != (*expected.JWTUser).Surname {
				t.Errorf("jwtUser does not match")
				return
			}
		}

		return
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Errorf("could not read expected unauthorized body %v", err)
	}

	received := string(body)
	expectedBody := `{"error":"Unauthorized"}`
	if received != expectedBody {
		t.Errorf("unauthorized body was not received correctly. expected: %s, received %s", expectedBody, received)
	}
}

func TestSuccessAuthHybridFirstSecret(t *testing.T) {
	ts := httptest.NewServer(authHybridTestFixture().HandlerFunc())
	defer ts.Close()

	req := helpers.JWTRequestTest(
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE1NjkzMDI5MDYsImV4cCI6NDEyNTM2MDUwNiwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsIkdpdmVuTmFtZSI6IkpvaG5ueSIsIlN1cm5hbWUiOiJSb2NrZXQiLCJFbWFpbCI6Impyb2NrZXRAZXhhbXBsZS5jb20iLCJSb2xlIjpbIk1hbmFnZXIiLCJQcm9qZWN0IEFkbWluaXN0cmF0b3IiXX0.tsJ6DZ80BtMzEO0SejB3guyXIQ1cgioQSDYlxLWTJdk",
		http.MethodGet,
		ts.URL,
		nil,
	)
	res := helpers.DoRequestTest(req)

	if res.StatusCode == http.StatusUnauthorized {
		t.Errorf("did not allow access to handler")
	}
	checkAuthHybridResponse(res, &authHybridResponseModel{
		JWTUser:        &testUserModel{GivenName: "Johnny", Surname: "Rocket"},
		IsAuthBasic:    false,
		IsAuthJWT:      false,
		IsAuth_jwt1:    true,
		IsAuth_jwt2:    false,
		IsAuth_jwt1Get: false,
		IsAuth_jwt2Get: false,
	}, t)
}

func TestSuccessAuthHybridSecondSecret(t *testing.T) {
	ts := httptest.NewServer(authHybridTestFixture().HandlerFunc())
	defer ts.Close()

	req := helpers.JWTRequestTest(
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE1NjkzMDI5MDYsImV4cCI6NDEyNTM2MDUwNiwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsIkdpdmVuTmFtZSI6IkpvaG5ueSIsIlN1cm5hbWUiOiJSb2NrZXQiLCJFbWFpbCI6Impyb2NrZXRAZXhhbXBsZS5jb20iLCJSb2xlIjpbIk1hbmFnZXIiLCJQcm9qZWN0IEFkbWluaXN0cmF0b3IiXX0.HJbowEi9q3YOKlsKftKsRYt0xwnK5DEm-2Nhff06N-8",
		http.MethodGet,
		ts.URL,
		nil,
	)
	res := helpers.DoRequestTest(req)

	if res.StatusCode == http.StatusUnauthorized {
		t.Errorf("did not allow access to handler")
	}
	checkAuthHybridResponse(res, &authHybridResponseModel{
		JWTUser:        &testUserModel{GivenName: "Johnny", Surname: "Rocket"},
		IsAuthBasic:    false,
		IsAuthJWT:      false,
		IsAuth_jwt1:    false,
		IsAuth_jwt2:    true,
		IsAuth_jwt1Get: false,
		IsAuth_jwt2Get: false,
	}, t)
}

func TestSuccessAuthHybridFirstSecretGet(t *testing.T) {
	ts := httptest.NewServer(authHybridTestFixture().HandlerFunc())
	defer ts.Close()

	req := helpers.JWTRequestGetTest(
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE1NjkzMDI5MDYsImV4cCI6NDEyNTM2MDUwNiwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsIkdpdmVuTmFtZSI6IkpvaG5ueSIsIlN1cm5hbWUiOiJSb2NrZXQiLCJFbWFpbCI6Impyb2NrZXRAZXhhbXBsZS5jb20iLCJSb2xlIjpbIk1hbmFnZXIiLCJQcm9qZWN0IEFkbWluaXN0cmF0b3IiXX0.tsJ6DZ80BtMzEO0SejB3guyXIQ1cgioQSDYlxLWTJdk",
		http.MethodGet,
		ts.URL,
		nil,
	)
	res := helpers.DoRequestTest(req)

	if res.StatusCode == http.StatusUnauthorized {
		t.Errorf("did not allow access to handler")
	}
	checkAuthHybridResponse(res, &authHybridResponseModel{
		JWTUser:        &testUserModel{GivenName: "Johnny", Surname: "Rocket"},
		IsAuthBasic:    false,
		IsAuthJWT:      false,
		IsAuth_jwt1:    false,
		IsAuth_jwt2:    false,
		IsAuth_jwt1Get: true,
		IsAuth_jwt2Get: false,
	}, t)
}

func TestSuccessAuthHybridSecondSecretGet(t *testing.T) {
	ts := httptest.NewServer(authHybridTestFixture().HandlerFunc())
	defer ts.Close()

	req := helpers.JWTRequestGetTest(
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE1NjkzMDI5MDYsImV4cCI6NDEyNTM2MDUwNiwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsIkdpdmVuTmFtZSI6IkpvaG5ueSIsIlN1cm5hbWUiOiJSb2NrZXQiLCJFbWFpbCI6Impyb2NrZXRAZXhhbXBsZS5jb20iLCJSb2xlIjpbIk1hbmFnZXIiLCJQcm9qZWN0IEFkbWluaXN0cmF0b3IiXX0.HJbowEi9q3YOKlsKftKsRYt0xwnK5DEm-2Nhff06N-8",
		http.MethodGet,
		ts.URL,
		nil,
	)
	res := helpers.DoRequestTest(req)

	if res.StatusCode == http.StatusUnauthorized {
		t.Errorf("did not allow access to handler")
	}
	checkAuthHybridResponse(res, &authHybridResponseModel{
		JWTUser:        &testUserModel{GivenName: "Johnny", Surname: "Rocket"},
		IsAuthBasic:    false,
		IsAuthJWT:      false,
		IsAuth_jwt1:    false,
		IsAuth_jwt2:    false,
		IsAuth_jwt1Get: false,
		IsAuth_jwt2Get: true,
	}, t)
}

func TestFailureAuthHybridJWT(t *testing.T) {
	ts := httptest.NewServer(authHybridTestFixture().HandlerFunc())
	defer ts.Close()

	req := helpers.JWTRequestTest(
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE1NjkzMDI5MDYsImV4cCI6NDEyNTM2MDUwNiwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsIkdpdmuTmFtZSI6IkpvaG5ueSIsIlN1cm5hbWUiOiJSb2NrZXQiLCJFbWFpbCI6Impyb2NrZXRAZXhhbXBsZS5jb20iLCJSb2xlIjpbIk1hbmFnZXIiLCJQcm9qZWN0IEFkbWluaXN0cmF0b3IiXX0.HJbowEi9q3YOKlsKftKsRYt0xwnK5DEm-2Nhff06N-8",
		http.MethodGet,
		ts.URL,
		nil,
	)
	res := helpers.DoRequestTest(req)

	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("did allow access to handler")
	}
	checkAuthHybridResponse(res, nil, t)
}

func TestSuccessAuthHybridBasic(t *testing.T) {
	ts := httptest.NewServer(authHybridTestFixture().HandlerFunc())
	defer ts.Close()
	req := helpers.AuthBasicRequestTest("testUser", "testPassword", http.MethodGet, ts.URL, nil)
	res := helpers.DoRequestTest(req)
	if res.StatusCode == http.StatusUnauthorized {
		t.Errorf("did not allow access to handler")
	}
	checkAuthHybridResponse(res, &authHybridResponseModel{
		BasicUser:      "testUser",
		IsAuthBasic:    true,
		IsAuthJWT:      false,
		IsAuth_jwt1:    false,
		IsAuth_jwt2:    false,
		IsAuth_jwt1Get: false,
		IsAuth_jwt2Get: false,
	}, t)
}

func TestFailureAuthHybridBasic(t *testing.T) {
	ts := httptest.NewServer(authBasicFixture().HandlerFunc())
	defer ts.Close()
	req := helpers.AuthBasicRequestTest("testUser1", "testPassword", http.MethodGet, ts.URL, nil)
	res := helpers.DoRequestTest(req)
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("did allow access to handler")
	}
	checkAuthHybridResponse(res, nil, t)
}
