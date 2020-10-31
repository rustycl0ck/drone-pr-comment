package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"testing"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

func ptr(s string) *string {
	return &s
}

func TestPostComment(t *testing.T) {
	logger = log.With(log.NewJSONLogger(os.Stdout), "time", log.DefaultTimestampUTC, "caller", log.DefaultCaller)
	level.Debug(logger).Log("test", "test")

	rsaKeyFile = ptr(os.Getenv("PLUGIN_RSA_KEY_FILE"))
	rsaKeyString = ptr(os.Getenv("PLUGIN_RSA_KEY"))
	appID = ptr(os.Getenv("PLUGIN_APP_ID"))
	ghHost = ptr(os.Getenv("PLUGIN_ENTERPRISE_GH_HOST"))
	repoOwner = ptr(os.Getenv("DRONE_REPO_OWNER"))
	repoName = ptr(os.Getenv("DRONE_REPO_NAME"))
	prNumber = ptr(os.Getenv("DRONE_PULL_REQUEST"))

	if *ghHost == "" {
		apiServer = "https://api.github.com"
	} else {
		apiServer = *ghHost + "/api/v3"
	}

	comment := "Test comment by Drone Build Number: " + os.Getenv("DRONE_BUILD_NUMBER")

	installationID := getAppInstallationID()
	token := getToken(installationID)
	apiURL, _ := postComment(token, comment)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		t.Errorf("Failed to create http client. err: %w", err)
	}
	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("Accept", "application/vnd.github.v3+json")
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}}
	resp, err := client.Do(req)
	if err != nil {
		t.Errorf("Failed to get reponse from server. err: %w", err)
	}
	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Errorf("Status code mismatch. Expected: %d, Got: %s", http.StatusOK, resp.Status)
	}

	var respObj map[string]interface{}
	if err := json.Unmarshal(body, &respObj); err != nil {
		t.Errorf("Failed to unmarshal response body to json. body: %s\nerr: %w", string(body), err)
	}

	postedComment, ok := respObj["body"].(string)
	if !ok {
		t.Errorf("Failed to get 'body' from response object: %v", respObj)
	}

	if postedComment != comment {
		t.Errorf("Posted comment does not match. Expected: %s, Got: %s", comment, postedComment)
	}
}
