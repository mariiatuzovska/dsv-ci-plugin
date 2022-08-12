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

// defaultTimeout defines default timeout for HTTP requests.
const defaultTimeout = time.Second * 5

var githubCI, gitlabCI bool = false, false

func main() {
	switch {
	case os.Getenv("GITHUB_ACTION") != "":
		githubCI = true
		actionInfo("🐣 Starting work with GITHUB")
	case os.Getenv("GITLAB_CI") != "":
		gitlabCI = true
		actionInfo("🐣 Starting work with GITLAB")
	default:
		actionStringError("🤡 Unknown CI server name")
		os.Exit(1)
	}

	// Tenant domain name (e.g. example.secretsvaultcloud.com).
	domain := os.Getenv("DOMAIN")
	if domain == "" {
		actionStringError("domain must be specified")
		os.Exit(1)
	}
	// Client ID for authentication.
	clientId := os.Getenv("CLIENT_ID")
	if clientId == "" {
		actionStringError("clientId must be specified")
		os.Exit(1)
	}
	// Client Secret for authentication.
	clientSecret := os.Getenv("CLIENT_SECRET")
	if clientSecret == "" {
		actionStringError("clientSecret must be specified")
		os.Exit(1)
	}
	// Data to retrieve from DSV in format `<path> <data key> as <output key>`.
	retrieve := os.Getenv("RETRIEVE")
	if retrieve == "" {
		actionStringError("retrieve string must be specified")
		os.Exit(1)
	}
	// Set environment variables in GITHUB. Required GITHUB_ENV environment variable to be a valid path to a file.
	setEnv := false
	if (githubCI && os.Getenv("SET_ENV") != "") || gitlabCI {
		setEnv = true
	}
	retrieveData, err := parseRetrieveFlag(retrieve)
	if err != nil {
		actionError(err)
		os.Exit(1)
	}
	actionDebugf("retrieve: %#v\n", retrieveData)
	if err := run(domain, clientId, clientSecret, setEnv, retrieveData); err != nil {
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

	envFile, err := actionOpenEnvFile(setEnv)
	if err != nil {
		return err
	}
	defer envFile.Close()

	actionInfo("✨ Fetching secret(s) from DSV...")
	for path, dataMap := range retrieveData {
		actionDebugf("Fetching secret at path %q", path)

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
				actionExportVariable(envFile, outputKey, secretValue)
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
	return secret, nil
}

func actionDebug(s string) {
	if githubCI {
		fmt.Printf("::debug::%s\n", s)
	}
}

func actionDebugf(format string, args ...interface{}) {
	actionDebug(fmt.Sprintf(format, args...))
}

func actionInfo(s string) {
	fmt.Println(s)
}

func actionError(err error) {
	if githubCI {
		fmt.Printf("::error::%v\n", err)
	} else if gitlabCI {
		fmt.Printf("🐞 %v\n", err)
	}
}

func actionStringError(s string) {
	if githubCI {
		fmt.Printf("::error::%s\n", s)
	} else if gitlabCI {
		fmt.Printf("🐞 %s\n", s)
	}
}

func actionSetOutput(key, val string) {
	if githubCI {
		fmt.Printf("::set-output name=%s::%s\n", key, val)
		actionDebugf("Output key %s has been set", key)
	}
}

func actionOpenEnvFile(setEnv bool) (*os.File, error) {
	var (
		envFile *os.File
		err     error
	)
	if gitlabCI {
		jobName := os.Getenv("CI_JOB_NAME")
		actionDebugf("opening file %s.env", jobName)
		if jobName == "" {
			return nil, fmt.Errorf("CI_JOB_NAME environment is not defined")
		}
		envFile, err = os.OpenFile(jobName+".env", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return nil, fmt.Errorf("cannot open file %s: %v", jobName+".env", err)
		}
	} else if githubCI && setEnv {
		envFileName := os.Getenv("GITHUB_ENV")
		if envFileName == "" {
			return nil, fmt.Errorf("GITHUB_ENV environment file is not defined")
		}
		envFile, err = os.OpenFile(envFileName, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return nil, fmt.Errorf("cannot open file %s: %v", envFileName, err)
		}
	}
	return envFile, nil
}

func actionExportVariable(envFile *os.File, key, val string) {
	if _, err := envFile.WriteString(fmt.Sprintf("%s=%s\n", strings.ToUpper(key), val)); err != nil {
		actionError(fmt.Errorf("could not update %s environment file: %v", envFile.Name(), err))
	}
	actionDebugf("Environment variable %s has been set", strings.ToUpper(key))
}
