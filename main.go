package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"time"

	"gopkg.in/alecthomas/kingpin.v2"

	jwt "github.com/dgrijalva/jwt-go/v4"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

// provided by govvv at build time
var GitCommit, GitBranch, GitSummary, BuildDate string

var (
	logger        = log.With(log.NewJSONLogger(os.Stdout), "time", log.DefaultTimestampUTC, "caller", log.DefaultCaller)
	rsaKeyFile    = kingpin.Flag("rsa-key-file", "RSA private key file").Envar("PLUGIN_RSA_KEY_FILE").ExistingFile()
	rsaKeyString  = kingpin.Flag("rsa-key", "RSA private key").Envar("PLUGIN_RSA_KEY").String()
	appID         = kingpin.Flag("app-id", "Github App ID").Envar("PLUGIN_APP_ID").String()
	ghHost        = kingpin.Flag("enterprise-gh-host", "Enterprise Github Server URL").Envar("PLUGIN_ENTERPRISE_GH_HOST").String()
	skipTLSVerify = kingpin.Flag("skip-tls-verification", "Skip the TLS certificate verification of the enterprise github server").Envar("PLUGIN_SKIP_TLS_VERIFY").Default("false").Bool()
	repoOwner     = kingpin.Flag("repo-owner", "Repository owner").Envar("DRONE_REPO_OWNER").String()
	repoName      = kingpin.Flag("repo-name", "Repository name").Envar("DRONE_REPO_NAME").String()
	prNumber      = kingpin.Flag("issue-number", "Pull-Request or Issue number").Envar("DRONE_PULL_REQUEST").String()
	commentString = kingpin.Flag("comment", "Comment text").Envar("PLUGIN_COMMENT_TEXT").String()
	commentFile   = kingpin.Flag("comment-file", "Comment text will be read from this file").Envar("PLUGIN_COMMMENT_FILE").ExistingFile()
)

func main() {
	version := fmt.Sprintf("%10s: %s\n%10s: %s\n%10s: %s\n%10s: %s\n", "version", GitSummary, "build_date", BuildDate, "branch", GitBranch, "commit", GitCommit)
	kingpin.Version(version)
	kingpin.Parse()

	level.Info(logger).Log("msg", "Version info", "git_summary", GitSummary, "git_commit", GitCommit, "git_branch", GitBranch, "build_date", BuildDate)

	var comment string
	if *commentString != "" {
		comment = *commentString
	}
	if *commentFile != "" {
		s, err := ioutil.ReadFile(*commentFile)
		if err != nil {
			level.Error(logger).Log("msg", "Failed to read comment text from file", "err", err)
		} else {
			comment = comment + string(s)
		}
	}
	level.Info(logger).Log("comment", comment)

	installationID := getAppInstallationID()
	token := getToken(installationID)
	postComment(token, comment)
}

func postComment(token, comment string) {

	endpoint := *ghHost + "/api/v3/repos/" + *repoOwner + "/" + *repoName + "/issues" + "/" + *prNumber + "/comments"

	tlsConfig := &tls.Config{
		InsecureSkipVerify: *skipTLSVerify,
	}

	tr := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: tlsConfig,
	}

	client := &http.Client{Transport: tr}

	reqBody, err := json.Marshal(map[string]string{
		"body": comment,
	})

	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(reqBody))
	if err != nil {
		level.Error(logger).Log("msg", "Failed to create http client", "err", err)
		os.Exit(1)
	}
	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("Accept", "application/vnd.github.v3+json")
	_, err = client.Do(req)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to get reponse from server", "err", err)
		os.Exit(1)
	}
	// body, err := ioutil.ReadAll(resp.Body)
	// level.Debug(logger).Log("response", string(body), "request", req.URL)
}

func getJWT() string {
	var rsaKeyContent []byte
	if *rsaKeyString != "" {
		rsaKeyContent = []byte(*rsaKeyString)
	} else if *rsaKeyFile != "" {
		contents, err := ioutil.ReadFile(*rsaKeyFile)
		if err != nil {
			level.Error(logger).Log("msg", "Failed to read RSA Key File contents", "err", err)
		} else {
			rsaKeyContent = contents
		}
	} else {
		level.Error(logger).Log("msg", "No RSA key provided")
		os.Exit(1)
	}

	rsaKey, err := jwt.ParseRSAPrivateKeyFromPEM(rsaKeyContent)
	if err != nil {
		level.Error(logger).Log("msg", "Could not parse thee RSA key", "err", err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256,
		jwt.StandardClaims{
			Issuer:    *appID,
			IssuedAt:  jwt.At(time.Now().Round(time.Second)),
			ExpiresAt: jwt.At(time.Now().Round(time.Second).Add(5 * time.Minute)),
		})
	ss, err := token.SignedString(rsaKey)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to create a signed string", "err", err)
	}
	return ss
}

func getAppInstallationID() string {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: *skipTLSVerify,
	}

	tr := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: tlsConfig,
	}

	client := &http.Client{Transport: tr}

	endpoint := *ghHost + "/api/v3" + "/repos/" + *repoOwner + "/" + *repoName + "/installation"
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to create http client", "err", err)
		os.Exit(1)
	}
	req.Header.Add("Authorization", "Bearer "+getJWT())
	req.Header.Add("Accept", "application/vnd.github.machine-man-preview+json")

	resp, err := client.Do(req)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to get reponse from server", "err", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to read response body", "err", err)
	}
	// level.Debug(logger).Log("response", string(body), "request", req.URL)

	var respObj map[string]interface{}
	if err := json.Unmarshal(body, &respObj); err != nil {
		level.Error(logger).Log("msg", "Failed to unmarshal response body to json", "err", err, "body", string(body))
	}

	retVal, ok := respObj["id"].(float64)
	if !ok {
		level.Error(logger).Log("msg", "Failed to get 'id' from response object", "reponse_object", respObj)
	}
	return strconv.FormatFloat(retVal, 'f', -1, 64)
}

func getToken(installationID string) string {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: *skipTLSVerify,
	}

	tr := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: tlsConfig,
	}

	client := &http.Client{Transport: tr}

	endpoint := *ghHost + "/api/v3" + "/app/installations" + "/" + installationID + "/access_tokens"
	req, err := http.NewRequest("POST", endpoint, nil)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to create http client", "err", err)
		os.Exit(1)
	}
	req.Header.Add("Authorization", "Bearer "+getJWT())
	req.Header.Add("Accept", "application/vnd.github.machine-man-preview+json")

	resp, err := client.Do(req)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to get reponse from server", "err", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to read response body", "err", err)
	}
	// level.Debug(logger).Log("response", string(body), "request", req.URL)

	var respObj map[string]interface{}
	if err := json.Unmarshal(body, &respObj); err != nil {
		level.Error(logger).Log("msg", "Failed to unmarshal response body to json", "err", err, "body", string(body))
	}

	retVal, ok := respObj["token"].(string)
	if !ok {
		level.Error(logger).Log("msg", "Failed to get 'id' from response object", "reponse_object", respObj)
	}
	return retVal
}
