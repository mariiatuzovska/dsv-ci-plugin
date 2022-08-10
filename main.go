package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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
	retrieve := os.Getenv("RETRIEVE")
	if retrieve == "" {
		fmt.Println("retrieve string must be specified")
		os.Exit(1)
	}
	retrieveData, err := parseRetrieveFlag(retrieve)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if err := run(server, clientId, clientSecret, retrieveData); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	forever := make(chan bool)
	<-forever
}

func run(server, clientId, clientSecret string, retrieveData map[string]map[string]string) error {
	apiEndpoint := fmt.Sprintf("https://%s/v1", server)
	httpClient := &http.Client{Timeout: DefaultTimeout}

	token, err := dsvGetToken(httpClient, apiEndpoint, clientId, clientSecret)
	if err != nil {
		return fmt.Errorf("authentication failed: %v", err)
	}

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
			os.Setenv(strings.ToUpper(outputKey), secretValue)
		}
	}
	return nil
}

func parseRetrieveFlag(retrieve string) (map[string]map[string]string, error) {
	result := make(map[string]map[string]string)
	retrieve = strings.ReplaceAll(retrieve, "\t", " ")
	mustCompile := regexp.MustCompile(`^[a-zA-Z0-9:\/@\+._-]+$`)
	for _, row := range strings.Split(retrieve, "\n") {
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
		if !mustCompile.MatchString(secretPath) {
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
