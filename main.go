package main

import (
	"bytes"
	"encoding/json"
	"flag"
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

var (
	server        = flag.String("server", "", "Secret server")
	clientId      = flag.String("clientId", "", "Client ID")
	clientSecret  = flag.String("clientSecret", "", "Client secret")
	secretPath    = flag.String("secretPath", "", "Secret path")
	secretDataKey = flag.String("secretDataKey", "", "Field name for a value to be retrieved from thr secret data for a given secret by secretPath")
)

func main() {
	flag.Parse()
	if err := run(); err != nil {
		actionError(err)
		os.Exit(1)
	}
}

func run() error {
	apiEndpoint := fmt.Sprintf("https://%s/v1", *server)

	httpClient := &http.Client{
		Timeout: DefaultTimeout,
	}

	// getting access token
	body := []byte(fmt.Sprintf(`{
		"grant_type":		"client_credentials",
		"client_id":		"%s",
		"client_secret":	"%s"
	}`, *clientId, *clientSecret))

	tokenResp, err := httpClient.Post(apiEndpoint+"/token", "application/json", bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	if tokenResp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST %s/token error: %d", apiEndpoint, tokenResp.StatusCode)
	}

	body, _ = io.ReadAll(tokenResp.Body)
	tokenRespData := make(map[string]interface{})
	json.Unmarshal(body, &tokenRespData)

	token, strExists := tokenRespData["accessToken"].(string)
	if !strExists {
		return fmt.Errorf("cannot get access token")
	}

	// getting secret
	secretRequest, err := http.NewRequest(http.MethodGet, apiEndpoint+"/secrets/"+*secretPath, nil)
	if err != nil {
		return err
	}
	secretRequest.Header.Set("Content-Type", "application/json")
	secretRequest.Header.Set("Authorization", token)

	secretResp, err := httpClient.Do(secretRequest)
	if err != nil {
		return err
	}
	if secretResp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s/secrets/%s error: %d", apiEndpoint, *secretPath, secretResp.StatusCode)
	}

	body, _ = io.ReadAll(secretResp.Body)
	secretRespData := make(map[string]interface{})
	json.Unmarshal(body, &secretRespData)

	secretData, dataExists := secretRespData["data"].(map[string]interface{})
	if !dataExists {
		return fmt.Errorf("cannot get secret data from '%s' secret", *secretPath)
	}
	secretValue, valExists := secretData[*secretDataKey].(string)
	if !valExists {
		return fmt.Errorf("cannot get '%s' from '%s' secret data", *secretDataKey, *secretPath)
	}

	actionSetOutput("secretVal", secretValue)
	actionExportVariable("secretEnvVal", secretValue)
	return nil
}

// Workflow commands:

func actionError(err error) {
	fmt.Printf("::error::%v\n", err)
}

func actionStringError(s string) {
	fmt.Printf("::error::%s\n", s)
}

func actionSetOutput(key, val string) {
	fmt.Printf("::set-output name=%s::%s\n", key, val)
}

func actionExportVariable(key, val string) {
	envFile := os.Getenv("GITHUB_ENV")
	if envFile == "" {
		actionStringError("GITHUB_ENV environment file is not defined")
		return
	}

	f, err := os.OpenFile(envFile, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		actionError(fmt.Errorf("could not open GITHUB_ENV environment file: %v", err))
		return
	}
	defer f.Close()

	if _, err = f.WriteString(fmt.Sprintf("%s=%s", key, val)); err != nil {
		actionError(fmt.Errorf("could not update GITHUB_ENV environment file: %v", err))
		return
	}
}
