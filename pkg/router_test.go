package pkg

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPublicRoutes(t *testing.T) {
	// Create new httptest writer
	w := httptest.NewRecorder()

	tests := []struct {
		name         string
		r            *http.Request
		expectedCode int
	}{
		{
			name:         "1: Test Get All Users",
			r:            newRequest(t, "GET", fmt.Sprintf("/%s/u", TestAPI.Options.Version), nil),
			expectedCode: 200,
		},
		{
			name:         "2: Test Get User by ID",
			r:            newRequest(t, "GET", fmt.Sprintf("/%s/u/1", TestAPI.Options.Version), nil),
			expectedCode: 200,
		},
		{
			name:         "3: Test Get User by Username",
			r:            newRequest(t, "GET", fmt.Sprintf("/%s/u/test123", TestAPI.Options.Version), nil),
			expectedCode: 200,
		},
		{
			name:         "4: Test Get All Images",
			r:            newRequest(t, "GET", fmt.Sprintf("/%s/images", TestAPI.Options.Version), nil),
			expectedCode: 200,
		},
		{
			name:         "5: Test Get All Captions",
			r:            newRequest(t, "GET", fmt.Sprintf("/%s/captions", TestAPI.Options.Version), nil),
			expectedCode: 200,
		},
		{
			name:         "6: Test Create User",
			r:            newRequest(t, "POST", fmt.Sprintf("/%s/u", TestAPI.Options.Version), nil),
			expectedCode: 200,
		},
		{
			name:         "7: Test Login",
			r:            newRequest(t, "POST", fmt.Sprintf("/%s/u/login", TestAPI.Options.Version), nil),
			expectedCode: 200,
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

func TestAuthenticatedRoutes(t *testing.T) {
	// Create new httptest writer
	w := httptest.NewRecorder()

	testUser := User{Username: "testingtheapi", Email: "testing_the_api123@gmail.com", Password: "!Testing123"}
	testLogin, _ := json.Marshal(User{Username: "testingtheapi", Password: "!Testing123"})
	testImage := Image{Slug: "test-image", Source: "google.com", PostedBy: testUser.ID}
	testCreateImage, _ := json.Marshal(testImage)
	testImage.Source = "google.com"
	testUpdateImage, _ := json.Marshal(testImage)

	tests := []struct {
		name         string
		r            *http.Request
		expectedCode int
	}{
		{
			name: "1. Test User Login",
			r: newRequest(t, "POST", fmt.Sprintf("/%s/u/login", TestAPI.Options.Version),
				bytes.NewBuffer(testLogin)),
			expectedCode: 200,
		},
		{
			name: "2. Test Create Image",
			r: newRequest(t, "POST", fmt.Sprintf("/%s/images", TestAPI.Options.Version),
				bytes.NewBuffer(testCreateImage)),
			expectedCode: 200,
		},
		{
			name: "3. Test Update Image",
			r: newRequest(t, "PATCH", fmt.Sprintf("/%s/images/%s", TestAPI.Options.Version, testImage.Slug),
				bytes.NewBuffer(testUpdateImage)),
			expectedCode: 200,
		},
		{
			name: "4. Test Delete Image",
			r: newRequest(t, "DELETE", fmt.Sprintf("/%s/images/%s", TestAPI.Options.Version, testImage.Slug),
				nil),
			expectedCode: 200,
		},
		{
			name: "5. Test Delete User",
			r: newRequest(t, "DELETE", fmt.Sprintf("/%s/u/%s", TestAPI.Options.Version, testUser.Username),
				nil),
			expectedCode: 200,
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

func TestBadRequests(t *testing.T) {
	// Create new httptest writer
	w := httptest.NewRecorder()

	tests := []struct {
		name         string
		r            *http.Request
		expectedCode int
	}{
		{
			name:         "Test nil Login",
			r:            newRequest(t, "POST", fmt.Sprintf("/%s/u/login", TestAPI.Options.Version), nil),
			expectedCode: 400,
		},
		{
			name:         "Test nil Image",
			r:            newRequest(t, "POST", fmt.Sprintf("/%s/images", TestAPI.Options.Version), nil),
			expectedCode: 400,
		},
		{
			name:         "Test nil User",
			r:            newRequest(t, "POST", fmt.Sprintf("/%s/u", TestAPI.Options.Version), nil),
			expectedCode: 400,
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

func TestNotFoundHandler(t *testing.T) {
	// Create new httptest writer
	w := httptest.NewRecorder()

	// Test nil login
	req, _ := http.NewRequest("GET", "/yamomma", nil)
	TestAPI.Options.Router.ServeHTTP(w, req)
	if w.Code != 404 {
		t.Error(fmt.Sprintf("Expected response was %v, but got %v", 404, w.Code))
	}

}

func TestMethodNotAllowedHandler(t *testing.T) {
	// Create new httptest writer
	w := httptest.NewRecorder()

	tests := []struct {
		name         string
		r            *http.Request
		expectedCode int
	}{
		{
			name:         "Test PUT",
			r:            newRequest(t, "PUT", fmt.Sprintf("/%s/u", TestAPI.Options.Version), nil),
			expectedCode: 405,
		},
		{
			name:         "Test COPY",
			r:            newRequest(t, "COPY", fmt.Sprintf("/%s/u", TestAPI.Options.Version), nil),
			expectedCode: 405,
		},
		{
			name:         "Test LINK",
			r:            newRequest(t, "LINK", fmt.Sprintf("/%s/u", TestAPI.Options.Version), nil),
			expectedCode: 405,
		},
		{
			name:         "Test UNLINK",
			r:            newRequest(t, "UNLINK", fmt.Sprintf("/%s/u", TestAPI.Options.Version), nil),
			expectedCode: 405,
		},
		{
			name:         "Test HEAD",
			r:            newRequest(t, "HEAD", fmt.Sprintf("/%s/u", TestAPI.Options.Version), nil),
			expectedCode: 405,
		},
		{
			name:         "Test GET When Expecting POST",
			r:            newRequest(t, "GET", fmt.Sprintf("/%s/u/login", TestAPI.Options.Version), nil),
			expectedCode: 405,
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

func newRequest(t *testing.T, method, url string, body io.Reader) *http.Request {
	r, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
