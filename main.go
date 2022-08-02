package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
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
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// getting access token
	body := []byte(fmt.Sprintf(`{
		"grant_type":		"client_credentials",
		"client_id":		"%s",
		"client_secret":	"%s"
	}`, *clientId, *clientSecret))

	tokenResp, err := http.Post("https://"+*server+"/v1/token", "application/json", bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	if tokenResp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST https://%s/v1/token error: %d", *server, tokenResp.StatusCode)
	}

	body, _ = ioutil.ReadAll(tokenResp.Body)
	tokenRespData := make(map[string]interface{})
	json.Unmarshal(body, &tokenRespData)

	token, strExists := tokenRespData["accessToken"].(string)
	if !strExists {
		return fmt.Errorf("cannot get access token")
	}

	// getting secret
	secretRequest, err := http.NewRequest(http.MethodGet, "https://"+*server+"/v1/secrets/"+*secretPath, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	secretRequest.Header.Set("Content-Type", "application/json")
	secretRequest.Header.Set("Authorization", token)

	secretResp, err := new(http.Client).Do(secretRequest)
	if err != nil {
		return err
	}
	if secretResp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET https://%s/v1/secrets/%s error: %d", *server, *secretPath, secretResp.StatusCode)
	}

	body, _ = ioutil.ReadAll(secretResp.Body)
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

	fmt.Printf("::set-output name=secretVal::%s\n", secretValue)
	return nil
}
