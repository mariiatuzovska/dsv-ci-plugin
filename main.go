package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// defaultTimeout defines default timeout for HTTP requests.
const defaultTimeout = time.Second * 5

func main() {
	var (
		domain       = flag.String("domain", "", "Tenant domain name (e.g. example.secretsvaultcloud.com).")
		clientId     = flag.String("clientId", "", "Client ID for authentication.")
		clientSecret = flag.String("clientSecret", "", "Client Secret for authentication.")
		setEnv       = flag.Bool("setEnv", false, "Set environment variables. Required GITHUB_ENV environment variable to be a valid path to a file.")
		retrieve     = flag.String("retrieve", "", "Data to retrieve from DSV in format `<path> <data key> as <output key>`.")
	)
	flag.Parse()
	if *domain == "" {
		actionStringError("domain must be specified")
		os.Exit(1)
	}
	if *clientId == "" {
		actionStringError("clientId must be specified")
		os.Exit(1)
	}
	if *clientSecret == "" {
		actionStringError("clientSecret must be specified")
		os.Exit(1)
	}
	if *retrieve == "" {
		actionStringError("retrieve string must be specified")
		os.Exit(1)
	}
	retrieveData, err := parseRetrieveFlag(*retrieve)
	if err != nil {
		actionError(err)
		os.Exit(1)
	}
	if err := run(*domain, *clientId, *clientSecret, *setEnv, retrieveData); err != nil {
		actionError(err)
		os.Exit(1)
	}
}

func run(domain, clientId, clientSecret string, setEnv bool, retrieveData map[string]map[string]string) error {
	apiEndpoint := fmt.Sprintf("https://%s/v1", domain)
	httpClient := &http.Client{Timeout: defaultTimeout}

	actionInfo("🔑 Fetching access token...")
	token, err := dsvGetToken(httpClient, apiEndpoint, clientId, clientSecret)
	if err != nil {
		return fmt.Errorf("authentication failed: %v", err)
	}

	actionInfo("✨ Fetching secret(s) from DSV...")
	for path, dataMap := range retrieveData {
		secret, err := dsvGetSecret(httpClient, apiEndpoint, token, path)
		if err != nil {
			return fmt.Errorf("failed to fetch secret from DSV: %v", err)
		}
		secretData, ok := secret["data"].(map[string]interface{})
		if !ok {
			return fmt.Errorf("cannot get secret data from '%s' secret", path)
		}

		for secretDataKey, outputKey := range dataMap {
			secretValue, ok := secretData[secretDataKey].(string)
			if !ok {
				return fmt.Errorf("cannot get '%s' from '%s' secret data", secretDataKey, path)
			}
			actionSetOutput(outputKey, secretValue)
			if setEnv {
				actionExportVariable(outputKey, secretValue)
			}
		}
	}
	return nil
}

func parseRetrieveFlag(retrieve string) (map[string]map[string]string, error) {
	pathRegexp := regexp.MustCompile(`^[a-zA-Z0-9:\/@\+._-]+$`)
	whitespaces := regexp.MustCompile(`\s+`)

	result := make(map[string]map[string]string)

	for _, row := range strings.Split(retrieve, "\n") {
		row = strings.TrimSpace(row)
		if row == "" {
			continue
		}
		row = whitespaces.ReplaceAllString(row, " ")

		tokens := strings.Split(row, " ")

		if len(tokens) != 4 {
			return nil, fmt.Errorf("failed to parse '%s'. "+
				"each 'retrieve' row must contain '<secret path> <secret data key> as <output key>' separated by spaces and/or tabs", row)
		}

		var (
			path      = tokens[0]
			dataKey   = tokens[1]
			outputKey = tokens[3]
		)
		if !pathRegexp.MatchString(path) {
			return nil, fmt.Errorf("failed to parse secret path '%s': "+
				"secret path may contain only letters, numbers, underscores, dashes, @, pluses and periods separated by colon or slash",
				path)
		}

		if _, ok := result[path]; !ok {
			result[path] = make(map[string]string)
		}
		result[path][dataKey] = outputKey
	}

	return result, nil
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

func dsvGetToken(c httpClient, apiEndpoint, cid, csecret string) (string, error) {
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
	actionDebugf("POST %s: token has been read", endpoint)
	return token, nil
}

func dsvGetSecret(c httpClient, apiEndpoint, accessToken, secretPath string) (map[string]interface{}, error) {
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
	actionDebugf("GET %s: secret has been read", endpoint)
	return secret, nil
}

func actionDebug(s string) {
	fmt.Printf("::debug::%s\n", s)
}

func actionDebugf(format string, args ...interface{}) {
	actionDebug(fmt.Sprintf(format, args...))
}

func actionInfo(s string) {
	fmt.Println(s)
}

func actionError(err error) {
	fmt.Printf("::error::%v\n", err)
}

func actionStringError(s string) {
	fmt.Printf("::error::%s\n", s)
}

func actionSetOutput(key, val string) {
	fmt.Printf("::set-output name=%s::%s\n", key, val)
	actionDebugf("output key %s has been set", key)
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
	actionDebugf("environment variable %s has been set", key)
}
