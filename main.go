package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const (
	// DefaultTimeout defines default timeout for HTTP requests.
	DefaultTimeout = time.Second * 5
)

type HttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

func main() {
	server := os.Getenv("SERVER")
	if server == "" {
		fmt.Println("server must be specified")
		os.Exit(1)
	}
	clientId := os.Getenv("CLIENT_ID")
	if clientId == "" {
		fmt.Println("clientId must be specified")
		os.Exit(1)
	}
	clientSecret := os.Getenv("CLIENT_SECRET")
	if clientSecret == "" {
		fmt.Println("clientSecret must be specified")
		os.Exit(1)
	}
	if len(os.Args) < 3 {
		fmt.Println("retrieve arguments must be specified")
		os.Exit(1)
	}

	if err := run(server, clientId, clientSecret, os.Args[1:3]); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run(server, clientId, clientSecret string, retrieveData []string) error {
	apiEndpoint := fmt.Sprintf("https://%s/v1", server)
	httpClient := &http.Client{Timeout: DefaultTimeout}

	token, err := dsvGetToken(httpClient, apiEndpoint, clientId, clientSecret)
	if err != nil {
		return fmt.Errorf("authentication failed: %v", err)
	}

	secret, err := dsvGetSecret(httpClient, apiEndpoint, token, retrieveData[0])
	if err != nil {
		return fmt.Errorf("failed to fetch secret from DSV: %v", err)
	}
	secretData, dataExists := secret["data"].(map[string]interface{})
	if !dataExists {
		return fmt.Errorf("cannot get secret data from '%s' secret", retrieveData[0])
	}
	secretValue, valExists := secretData[retrieveData[1]].(string)
	if !valExists {
		return fmt.Errorf("cannot get '%s' from '%s' secret data", retrieveData[1], retrieveData[0])
	}
	if jobName := os.Getenv("CI_JOB_NAME"); jobName != "" {
		file, err := os.OpenFile(jobName+".env", os.O_CREATE|os.O_RDWR, os.ModePerm)
		if err != nil {
			return fmt.Errorf("cannot open file %s: %v", jobName+".env", err)
		}
		defer file.Close()
		_, err = file.WriteString(fmt.Sprintf("SECRET=%s\n", secretValue))
		if err != nil {
			return fmt.Errorf("cannot write to the file %s: %v", jobName+".env", err)
		}
	}
	return nil
}

func dsvGetToken(c HttpClient, apiEndpoint, cid, csecret string) (string, error) {
	body := []byte(fmt.Sprintf(
		`{"grant_type":"client_credentials","client_id":"%s","client_secret":"%s"}`,
		cid, csecret,
	))
	endpoint := apiEndpoint + "/token"
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("could not build request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Delinea-DSV-Client", "gh-action")

	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("API call failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("POST %s: %s", endpoint, resp.Status)
	}

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("could not read response body: %v", err)
	}
	tokenRespData := make(map[string]interface{})
	err = json.Unmarshal(body, &tokenRespData)
	if err != nil {
		return "", fmt.Errorf("could not unmarshal response body: %v", err)
	}

	token, strExists := tokenRespData["accessToken"].(string)
	if !strExists {
		return "", fmt.Errorf("could not read access token from response")
	}
	return token, nil
}

func dsvGetSecret(c HttpClient, apiEndpoint, accessToken, secretPath string) (map[string]interface{}, error) {
	endpoint := apiEndpoint + "/secrets/" + secretPath
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("could not build request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Delinea-DSV-Client", "gh-action")
	req.Header.Set("Authorization", accessToken)

	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API call failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", endpoint, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("could not read response body: %v", err)
	}
	secret := make(map[string]interface{})
	err = json.Unmarshal(body, &secret)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal response body: %v", err)
	}
	return secret, nil
}
