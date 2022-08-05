package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	// DefaultTimeout defines default timeout for HTTP requests.
	DefaultTimeout = time.Second * 5
)

var (
	server       = flag.String("server", "", "Secret server")
	clientId     = flag.String("clientId", "", "Client ID")
	clientSecret = flag.String("clientSecret", "", "Client Secret")
	setEnv       = flag.Bool("setEnv", false, "Specifies to set or do not set environment")
	retrieve     = flag.String("retrieve", "", "Secret paths and data keys")
)

func main() {
	flag.Parse()
	if err := run(); err != nil {
		actionError(err)
		os.Exit(1)
	}
}

func run() error {
	if err := validateInput(); err != nil {
		return err
	}
	retrieveData, err := parseRetrieveFlag()
	if err != nil {
		return err
	}

	apiEndpoint := fmt.Sprintf("https://%s/v1", *server)

	httpClient := &http.Client{Timeout: DefaultTimeout}

	log.Print("🔑 Fetching access token...")

	token, err := dsvGetToken(httpClient, apiEndpoint, *clientId, *clientSecret)
	if err != nil {
		return fmt.Errorf("authentication failed: %v", err)
	}

	log.Print("✨ Fetching secret(s) from DSV...")
	for secretPath, secretDataOutput := range retrieveData {
		secret, err := dsvGetSecret(httpClient, apiEndpoint, token, secretPath)
		if err != nil {
			return fmt.Errorf("failed to fetch secret from DSV: %v", err)
		}
		secretData, dataExists := secret["data"].(map[string]interface{})
		if !dataExists {
			return fmt.Errorf("cannot get secret data from '%s' secret", secretPath)
		}
		for secretDataKey, outputKey := range secretDataOutput {
			secretValue, valExists := secretData[secretDataKey].(string)
			if !valExists {
				return fmt.Errorf("cannot get '%s' from '%s' secret data", secretDataKey, secretPath)
			}
			actionSetOutput(outputKey, secretValue)
			if *setEnv {
				actionExportVariable(outputKey, secretValue)
			}
		}
	}
	return nil
}

func validateInput() error {
	if *server == "" {
		return fmt.Errorf("server must be specified")
	}
	serverPathTokens := strings.Split(*server, ".")
	for _, token := range serverPathTokens {
		if token == "" || len(serverPathTokens) < 3 {
			return fmt.Errorf("bad server input: '%s'", *server)
		}
	}
	if *clientId == "" {
		return fmt.Errorf("clientId must be specified")
	}
	if *clientSecret == "" {
		return fmt.Errorf("clientSecret must be specified")
	}
	if *retrieve == "" {
		return fmt.Errorf("retrieve must be specified")
	}
	return nil
}

func parseRetrieveFlag() (map[string]map[string]string, error) {
	result := make(map[string]map[string]string)
	for _, row := range strings.Split(*retrieve, "\n") {
		tokens := make([]string, 0, 4)
		for _, token := range strings.Split(row, " ") {
			if token != "" {
				tokens = append(tokens, token)
			}
		}
		if len(tokens) == 0 {
			continue
		} else if len(tokens) != 4 {
			return nil, fmt.Errorf("failed to parse '%s'. "+
				"each 'retrieve' row must contain '<secret path> <secret data key> as <output key>' separated by spaces", row)
		}

		var (
			secretPath    = tokens[0]
			secretDataKey = tokens[1]
			outputKey     = tokens[3]
		)
		if !regexp.MustCompile(`^[a-zA-Z0-9:\/@\+._-]+$`).MatchString(secretPath) {
			return nil, fmt.Errorf("failed to parse secret path '%s': "+
				"secret path may contain only letters, numbers, underscores, dashes, @, pluses and periods separated by colon or slash",
				secretPath)
		}
		if _, exists := result[secretPath]; !exists {
			result[secretPath] = make(map[string]string)
		}
		result[secretPath][secretDataKey] = outputKey
	}
	return result, nil
}

func dsvGetToken(c *http.Client, apiEndpoint, cid, csecret string) (string, error) {
	body := []byte(fmt.Sprintf(
		`{"grant_type":"client_credentials","client_id":"%s","client_secret":"%s"}`,
		*clientId, *clientSecret,
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

func dsvGetSecret(c *http.Client, apiEndpoint, accessToken, secretPath string) (map[string]interface{}, error) {
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
