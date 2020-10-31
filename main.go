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
	logger    log.Logger
	apiServer string

	rsaKeyFile    = kingpin.Flag("rsa-key-file", "RSA private key file").Envar("PLUGIN_RSA_KEY_FILE").ExistingFile()
	rsaKeyString  = kingpin.Flag("rsa-key", "RSA private key").Envar("PLUGIN_RSA_KEY").String()
	appID         = kingpin.Flag("app-id", "Github App ID").Envar("PLUGIN_APP_ID").String()
	ghHost        = kingpin.Flag("enterprise-gh-host", "Enterprise Github Server URL [Defaults to public github]").Envar("PLUGIN_ENTERPRISE_GH_HOST").String()
	skipTLSVerify = kingpin.Flag("skip-tls-verification", "Skip the TLS certificate verification of the enterprise github server").Envar("PLUGIN_SKIP_TLS_VERIFY").Default("false").Bool()
	repoOwner     = kingpin.Flag("repo-owner", "Repository owner").Envar("DRONE_REPO_OWNER").String()
	repoName      = kingpin.Flag("repo-name", "Repository name").Envar("DRONE_REPO_NAME").String()
	prNumber      = kingpin.Flag("issue-number", "Pull-Request or Issue number").Envar("DRONE_PULL_REQUEST").String()
	commentString = kingpin.Flag("comment", "Comment text").Envar("PLUGIN_COMMENT_TEXT").String()
	commentFile   = kingpin.Flag("comment-file", "Comment text will be read from this file").Envar("PLUGIN_COMMENT_FILE").ExistingFile()
	wrapAsCode    = kingpin.Flag("wrap-as-code", "Wrap the comment text in tripe backticks for rendering as markdown code").Envar("PLUGIN_COMMENT_WRAP_AS_CODE").Default("false").Bool()
	debug         = kingpin.Flag("debug", "Enable debug mode [WARNING: This will expose the 'Installation ID' of the github app in logs]").Envar("PLUGIN_DEBUG").Default("false").Bool()
	logFormat     = kingpin.Flag("log-format", "Valid log formats: [logfmt, json]").Envar("PLUGIN_LOG_FORMAT").Default("logfmt").Enum("logfmt", "json")
)

func main() {
	kingpin.Parse()

	version := fmt.Sprintf("%10s: %s\n%10s: %s\n%10s: %s\n%10s: %s\n", "version", GitSummary, "build_date", BuildDate, "branch", GitBranch, "commit", GitCommit)
	kingpin.Version(version)

	switch *logFormat {
	case "json":
		logger = log.NewJSONLogger(os.Stdout)
	case "logfmt":
		logger = log.NewLogfmtLogger(os.Stdout)
	}

	if *debug {
		logger = level.NewFilter(logger, level.AllowDebug())
	} else {
		logger = level.NewFilter(logger, level.AllowInfo())
	}

	logger = log.With(logger, "time", log.DefaultTimestampUTC, "caller", log.DefaultCaller)

	level.Info(logger).Log("msg", "Version info", "git_summary", GitSummary, "git_commit", GitCommit, "git_branch", GitBranch, "build_date", BuildDate)
	level.Debug(logger).Log("msg", "Running in debug mode")

	if *ghHost == "" {
		apiServer = "https://api.github.com"
		level.Info(logger).Log("msg", "Using public github")
	} else {
		apiServer = *ghHost + "/api/v3"
		level.Info(logger).Log("msg", "Using enterprise github")
	}
	level.Debug(logger).Log("github_url", apiServer)

	var comment string
	if *wrapAsCode {
		comment = comment + "```\n"
	}

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
	if *wrapAsCode {
		comment = comment + "\n```\n"
	}
	level.Info(logger).Log("comment", comment)

	installationID := getAppInstallationID()
	token := getToken(installationID)
	apiURL, htmlURL := postComment(token, comment)
	level.Info(logger).Log("html_url", htmlURL, "api_url", apiURL)
}

func postComment(token, comment string) (string, string) {

	endpoint := apiServer + "/repos/" + *repoOwner + "/" + *repoName + "/issues" + "/" + *prNumber + "/comments"

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
	resp, err := client.Do(req)
	if err != nil {
		level.Error(logger).Log("msg", "Failed to get reponse from server", "err", err)
		os.Exit(1)
	}
	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 201 {
		level.Debug(logger).Log("msg", "Failed to comment on issue", "response", string(body), "request", req.URL, "status_code", resp.Status)
		os.Exit(1)
	}

	var respObj map[string]interface{}
	if err := json.Unmarshal(body, &respObj); err != nil {
		level.Error(logger).Log("msg", "Failed to unmarshal response body to json", "err", err, "body", string(body))
	}

	htmlURL, ok := respObj["html_url"].(string)
	if !ok {
		level.Error(logger).Log("msg", "Failed to get 'html_url' from response object", "reponse_object", respObj, "status_code", resp.Status)
	}

	apiURL, ok := respObj["url"].(string)
	if !ok {
		level.Error(logger).Log("msg", "Failed to get 'url' from response object", "reponse_object", respObj, "status_code", resp.Status)
	}
	return apiURL, htmlURL
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

	endpoint := apiServer + "/repos/" + *repoOwner + "/" + *repoName + "/installation"
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
	level.Debug(logger).Log("request", req.URL)

	var respObj map[string]interface{}
	if err := json.Unmarshal(body, &respObj); err != nil {
		level.Error(logger).Log("msg", "Failed to unmarshal response body to json", "err", err, "body", string(body))
	}

	retVal, ok := respObj["id"].(float64)
	if !ok {
		level.Error(logger).Log("msg", "Failed to get 'id' from response object", "reponse_object", respObj, "status_code", resp.Status)
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

	endpoint := apiServer + "/app/installations" + "/" + installationID + "/access_tokens"
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
	level.Debug(logger).Log("request", req.URL)

	var respObj map[string]interface{}
	if err := json.Unmarshal(body, &respObj); err != nil {
		level.Error(logger).Log("msg", "Failed to unmarshal response body to json", "err", err, "body", string(body))
	}

	retVal, ok := respObj["token"].(string)
	if !ok {
		level.Error(logger).Log("msg", "Failed to get 'id' from response object", "reponse_object", respObj, "status_code", resp.Status)
	}
	return retVal
}
