package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"testing"
)

type MockHttpClient struct {
	response *http.Response
	err      error
}

func (m *MockHttpClient) Do(req *http.Request) (*http.Response, error) {
	return m.response, m.err
}

func TestDsvGetToken(t *testing.T) {
	cases := []struct {
		name        string
		apiEndpoint string
		cid         string
		csecret     string
		httpClient  HttpClient
		want        string
		wantErr     error
	}{
		{
			name:        "happy path",
			apiEndpoint: "test.example.com",
			cid:         "client_id",
			csecret:     "client_secret",
			httpClient: &MockHttpClient{
				response: &http.Response{
					Status:     "200 OK",
					StatusCode: 200,
					Body: io.NopCloser(bytes.NewReader([]byte(`{
						"accessToken": "token"
					}`))),
				},
				err: nil,
			},
			want:    "token",
			wantErr: nil,
		},
		{
			name:        "bad request",
			apiEndpoint: "test.example.com",
			cid:         "client_id",
			csecret:     "client_secret",
			httpClient: &MockHttpClient{
				response: &http.Response{
					Status:     "400 Bad Request",
					StatusCode: 400,
					Body:       io.NopCloser(bytes.NewReader([]byte(nil))),
				},
				err: nil,
			},
			want:    "",
			wantErr: fmt.Errorf("POST test.example.com/token: 400 Bad Request"),
		},
		{
			name:        "empty endpoint",
			apiEndpoint: "",
			cid:         "client_id",
			csecret:     "client_secret",
			httpClient: &MockHttpClient{
				response: &http.Response{
					Status:     "400 Bad Request",
					StatusCode: 400,
					Body:       io.NopCloser(bytes.NewReader([]byte(nil))),
				},
				err: nil,
			},
			want:    "",
			wantErr: fmt.Errorf("POST /token: 400 Bad Request"),
		},
		{
			name:        "http error",
			apiEndpoint: "test.example.com",
			cid:         "client_id",
			csecret:     "client_secret",
			httpClient: &MockHttpClient{
				response: nil,
				err:      fmt.Errorf("error"),
			},
			want:    "",
			wantErr: fmt.Errorf("API call failed: error"),
		},
		{
			name:        "nil body",
			apiEndpoint: "test.example.com",
			cid:         "client_id",
			csecret:     "client_secret",
			httpClient: &MockHttpClient{
				response: &http.Response{
					Status:     "200 OK",
					StatusCode: 200,
					Body:       io.NopCloser(bytes.NewReader([]byte(nil))),
				},
				err: nil,
			},
			want:    "",
			wantErr: fmt.Errorf("could not unmarshal response body: unexpected end of JSON input"),
		},
		{
			name:        "no access token",
			apiEndpoint: "test.example.com",
			cid:         "client_id",
			csecret:     "client_secret",
			httpClient: &MockHttpClient{
				response: &http.Response{
					Status:     "200 OK",
					StatusCode: 200,
					Body: io.NopCloser(bytes.NewReader([]byte(`{
						"test": "token"
					}`))),
				},
				err: nil,
			},
			want:    "",
			wantErr: fmt.Errorf("could not read access token from response"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := dsvGetToken(tc.httpClient, tc.apiEndpoint, tc.cid, tc.csecret)
			if (tc.wantErr != nil && tc.wantErr.Error() != err.Error()) || (tc.wantErr == nil && err != nil) {
				t.Errorf("want error %v, got %v", tc.wantErr, err)
			}
			if tc.want != result {
				t.Errorf("want %v, got %v", tc.want, result)
			}
		})
	}
}

func TestDsvGetSecret(t *testing.T) {
	cases := []struct {
		name        string
		httpClient  HttpClient
		apiEndpoint string
		accessToken string
		secretPath  string
		want        map[string]interface{}
		wantErr     error
	}{
		{
			name: "happy path",
			httpClient: &MockHttpClient{
				response: &http.Response{
					Status:     "200 OK",
					StatusCode: 200,
					Body: io.NopCloser(bytes.NewReader([]byte(`{
						"key": "val"
					}`))),
				},
				err: nil,
			},
			apiEndpoint: "test.example.com",
			accessToken: "token",
			secretPath:  "folder1/secret1",
			want: map[string]interface{}{
				"key": "val",
			},
			wantErr: nil,
		},
		{
			name: "bad request",
			httpClient: &MockHttpClient{
				response: &http.Response{
					Status:     "400 Bad Request",
					StatusCode: 400,
					Body:       io.NopCloser(bytes.NewReader([]byte(nil))),
				},
				err: nil,
			},
			apiEndpoint: "test.example.com",
			accessToken: "token",
			secretPath:  "folder1/secret1",
			want:        nil,
			wantErr:     fmt.Errorf("GET test.example.com/secrets/folder1/secret1: 400 Bad Request"),
		},
		{
			name: "http error",
			httpClient: &MockHttpClient{
				response: nil,
				err:      fmt.Errorf("error"),
			},
			apiEndpoint: "test.example.com",
			accessToken: "token",
			secretPath:  "folder1/secret1",
			want:        nil,
			wantErr:     fmt.Errorf("API call failed: error"),
		},
		{
			name: "nil body",
			httpClient: &MockHttpClient{
				response: &http.Response{
					Status:     "200 OK",
					StatusCode: 200,
					Body:       io.NopCloser(bytes.NewReader([]byte(nil))),
				},
				err: nil,
			},
			apiEndpoint: "test.example.com",
			accessToken: "token",
			secretPath:  "folder1/secret1",
			want:        nil,
			wantErr:     fmt.Errorf("could not unmarshal response body: unexpected end of JSON input"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := dsvGetSecret(tc.httpClient, tc.apiEndpoint, tc.accessToken, tc.secretPath)
			if (tc.wantErr != nil && tc.wantErr.Error() != err.Error()) || (tc.wantErr == nil && err != nil) {
				t.Errorf("want error %v, got %v", tc.wantErr, err)
			}
			if !reflect.DeepEqual(tc.want, result) {
				t.Errorf("want %v, got %v", tc.want, result)
			}
		})
	}
}
