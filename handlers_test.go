package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestTokenHandler(t *testing.T) {
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(TokenHandler)

	req, err := http.NewRequest("GET", "/token", nil)
	notErr(t, err)

	//check response
	handler.ServeHTTP(rr, req)

	checkStatus(t, rr, http.StatusOK)

	body := decodeResponse(t, rr)
	expectedBody := "You are authenticated"
	bodyEqual(t, expectedBody, body)

	//cookie
	if cookie := rr.HeaderMap.Get("Set-Cookie"); cookie == "" {
		t.Error("No 'token' cookie")
	}
}

func TestResourceHandlerUnauthorized(t *testing.T) {
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(authMiddleware(ResourceHandler))

	req, err := http.NewRequest("GET", "/resource", nil)
	notErr(t, err)

	req.Header.Set("Set-Cookie", "token="+"unknownToken")

	handler.ServeHTTP(rr, req)

	checkStatus(t, rr, http.StatusUnauthorized)

	body := decodeResponse(t, rr)
	expectedBody := "Unauthorized. Authenticate via \"/token\""
	bodyEqual(t, expectedBody, body)
}

func TestResourceHandlerAuthorized(t *testing.T) {
	token := getTokenRequest(t)
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(authMiddleware(ResourceHandler))

	req, err := http.NewRequest("GET", "/token", nil)
	notErr(t, err)

	req.Header.Set("Cookie", "token="+token)

	handler.ServeHTTP(rr, req)

	checkStatus(t, rr, http.StatusOK)

	body := decodeResponse(t, rr)
	expectedBody := "This is resource!"
	bodyEqual(t, expectedBody, body)
}

func getTokenRequest(t *testing.T) string {
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(TokenHandler)

	req, err := http.NewRequest("GET", "/token", nil)
	notErr(t, err)

	//check response
	handler.ServeHTTP(rr, req)

	checkStatus(t, rr, http.StatusOK)

	body := decodeResponse(t, rr)
	expectedBody := "You are authenticated"
	bodyEqual(t, expectedBody, body)

	//token
	token := rr.HeaderMap.Get("Set-Cookie")
	if token == "" {
		t.Error("No 'token' cookie")
	}

	return strings.Split(token, "=")[1]
}

func bodyEqual(t *testing.T, expect interface{}, real interface{}) bool {
	if !reflect.DeepEqual(expect, real) {
		t.Errorf("handler returned unexpected body: expected '%v', got '%v'", expect, real)
		return false
	}
	return true
}

func decodeResponse(t *testing.T, rr *httptest.ResponseRecorder) interface{} {
	reader := bytes.NewReader(rr.Body.Bytes())
	decoder := json.NewDecoder(reader)

	var f interface{}
	err := decoder.Decode(&f)
	if err != nil {
		t.Errorf("Decode response error: %v", err)
		return nil
	} else {
		return f
	}
}

func checkStatus(t *testing.T, rr *httptest.ResponseRecorder, expected int) bool {
	if status := rr.Code; status != status {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, expected)
		return false
	}
	return true
}

func notErr(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}
