package pkg

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestJWTMiddleware(t *testing.T) {
	w := httptest.NewRecorder()

	http.SetCookie(w, &http.Cookie{
		Name:  "token",
		Value: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImp0aSI6ImQ0MTIxYzIxLTQyMmEtNGUwYy1hOGE5LTY1NGIwNzk0YmRjYSIsImlhdCI6MTU0Nzc3MDY5NiwiZXhwIjoxNTQ3Nzc0Mjk2fQ.kQjSGPsz-GmlXC6aBwBAJjmjc0pyZo8qkAiypK_KkXU",
	})
	http.SetCookie(w, &http.Cookie{
		Name:  "session",
		Value: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImp0aSI6ImQ0MTIxYzIxLTQyMmEtNGUwYy1hOGE5LTY1NGIwNzk0YmRjYSIsImlhdCI6MTU0Nzc3MDY5NiwiZXhwIjoxNTQ3Nzc0Mjk2fQ.kQjSGPsz-GmlXC6aBwBAJjmjc0pyZo8qkAiypK_KkXU",
	})
	http.SetCookie(w, &http.Cookie{
		Name:  "user",
		Value: "test",
	})

	req, _ := http.NewRequest("POST", fmt.Sprintf("%s/images", TestAPI.Options.Version), nil)
	TestAPI.Options.Router.ServeHTTP(w, req)
}
