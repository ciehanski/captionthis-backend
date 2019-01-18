package pkg

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLogin(t *testing.T) {
	w := httptest.NewRecorder()

	// Login test user
	testUserJSON, _ := json.Marshal(User{Username: "testingtheapi", Password: "!Testing123"})
	req, _ := http.NewRequest("POST", fmt.Sprintf("/%s/u/login", TestAPI.Options.Version),
		bytes.NewBuffer(testUserJSON))
	TestAPI.Options.Router.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Error("Expected response was 200")
	}

	// Check cookies set on response
	cookies := w.Result().Cookies()
	if cookies[0].Value == "" || cookies[1].Value == "" || cookies[2].Value == "" {
		t.Error("Authentication cookies missing on response")
	}

	// Check cookies on subsequent request
	req, _ = http.NewRequest("GET", fmt.Sprintf("/%s/u", TestAPI.Options.Version), nil)
	TestAPI.Options.Router.ServeHTTP(w, req)
	_, err := req.Cookie("token")
	if err != nil {
		t.Error("Token cookie missing from request")
	}
	_, err = req.Cookie("session")
	if err != nil {
		t.Error("Session cookie missing from request")
	}
	_, err = req.Cookie("user")
	if err != nil {
		t.Error("User cookie missing from request")
	}
}

func TestCreateUser(t *testing.T) {
	// Create new httptest writer
	w := httptest.NewRecorder()

	testUsernameInUse, _ := json.Marshal(User{Username: "testingtheapi", Email: "testing_the_api123@gmail.com", Password: "!Testing123"})
	testEmailInUse, _ := json.Marshal(User{Username: "newtestuser", Email: "testing_the_api123@gmail.com", Password: "!Testing123"})
	testUsernameTooShort, _ := json.Marshal(User{Username: "te", Email: "testing_the_api123@gmail.com", Password: "!Testing123"})
	testUsernameTooLong, _ := json.Marshal(User{Username: "thisusernameistoolong", Email: "testing_the_api123@gmail.com", Password: "!Testing123"})
	testInvalidEmailNoDot, _ := json.Marshal(User{Username: "test", Email: "testing_the_api123@gmailcom", Password: "!Testing123"})
	testInvalidEmailNoAt, _ := json.Marshal(User{Username: "test", Email: "testing_the_api123gmail.com", Password: "!Testing123"})
	testInvalidEmailSymbols, _ := json.Marshal(User{Username: "test", Email: ":293hd93f;@gmail.com", Password: "!Testing123"})
	testInvalidPassNoSymbol, _ := json.Marshal(User{Username: "test", Email: "testing_the_api123@gmail.com", Password: "Testing123"})
	testInvalidPassNoCap, _ := json.Marshal(User{Username: "test", Email: "testing_the_api123@gmail.com", Password: "!testing123"})
	testInvalidPassNoNum, _ := json.Marshal(User{Username: "test", Email: "testing_the_api123@gmail.com", Password: "!Testingddd"})
	testInvalidPassTooShort, _ := json.Marshal(User{Username: "test", Email: "testing_the_api123@gmail.com", Password: "!T1dfg"})

	tests := []struct {
		name         string
		r            *http.Request
		expectedCode int
	}{
		{
			name: "1. Test Username Already In Use",
			r: newRequest(t, "POST", fmt.Sprintf("/%s/u", TestAPI.Options.Version),
				bytes.NewBuffer(testUsernameInUse)),
			expectedCode: 409,
		},
		{
			name: "2. Test Email Already In Use",
			r: newRequest(t, "POST", fmt.Sprintf("/%s/u", TestAPI.Options.Version),
				bytes.NewBuffer(testEmailInUse)),
			expectedCode: 409,
		},
		{
			name: "3. Test Username Too Short",
			r: newRequest(t, "POST", fmt.Sprintf("/%s/u", TestAPI.Options.Version),
				bytes.NewBuffer(testUsernameTooShort)),
			expectedCode: 409,
		},
		{
			name: "4. Test Username Too Long",
			r: newRequest(t, "POST", fmt.Sprintf("/%s/u", TestAPI.Options.Version),
				bytes.NewBuffer(testUsernameTooLong)),
			expectedCode: 409,
		},
		{
			name: "5. Test Invalid Email No Dot",
			r: newRequest(t, "POST", fmt.Sprintf("/%s/u", TestAPI.Options.Version),
				bytes.NewBuffer(testInvalidEmailNoDot)),
			expectedCode: 409,
		},
		{
			name: "6. Test Invalid Email No At",
			r: newRequest(t, "POST", fmt.Sprintf("/%s/u", TestAPI.Options.Version),
				bytes.NewBuffer(testInvalidEmailNoAt)),
			expectedCode: 409,
		},
		{
			name: "7. Test Invalid Email With Symbols",
			r: newRequest(t, "POST", fmt.Sprintf("/%s/u", TestAPI.Options.Version),
				bytes.NewBuffer(testInvalidEmailSymbols)),
			expectedCode: 409,
		},
		{
			name: "8. Test Invalid Password No Symbols",
			r: newRequest(t, "POST", fmt.Sprintf("/%s/u", TestAPI.Options.Version),
				bytes.NewBuffer(testInvalidPassNoSymbol)),
			expectedCode: 409,
		},
		{
			name: "9. Test Invalid Password No Capital",
			r: newRequest(t, "POST", fmt.Sprintf("/%s/u", TestAPI.Options.Version),
				bytes.NewBuffer(testInvalidPassNoCap)),
			expectedCode: 409,
		},
		{
			name: "10. Test Invalid Password No Number",
			r: newRequest(t, "POST", fmt.Sprintf("/%s/u", TestAPI.Options.Version),
				bytes.NewBuffer(testInvalidPassNoNum)),
			expectedCode: 409,
		},
		{
			name: "11. Test Invalid Password Too Short",
			r: newRequest(t, "POST", fmt.Sprintf("/%s/u", TestAPI.Options.Version),
				bytes.NewBuffer(testInvalidPassTooShort)),
			expectedCode: 409,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			TestAPI.Options.Router.ServeHTTP(w, tt.r)
			// check for expected response here.
			if w.Code != tt.expectedCode {
				t.Error(fmt.Sprintf("Expected response code %v, got %v", tt.expectedCode, w.Code))
			}
		})
	}
}

func TestUpdateUser(t *testing.T) {
	w := httptest.NewRecorder()

	// Login test user
	testUserJSON, _ := json.Marshal(User{Username: "testingtheapi", Password: "!Testing123"})
	req, _ := http.NewRequest("POST", fmt.Sprintf("/%s/u/login", TestAPI.Options.Version),
		bytes.NewBuffer(testUserJSON))
	TestAPI.Options.Router.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Error(fmt.Sprintf("Expected response was 200, but got %v", w.Code))
	}

	// Test create user that is already created
	testUserJSON, _ = json.Marshal(User{Email: "my_new_email_address@gmail.com"})
	req, _ = http.NewRequest("PATCH", fmt.Sprintf("/%s/u/%s", TestAPI.Options.Version, "testingtheapi"),
		bytes.NewBuffer(testUserJSON))
	TestAPI.Options.Router.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Error(fmt.Sprintf("Expected response was 200, but got %v", w.Code))
	}
}
