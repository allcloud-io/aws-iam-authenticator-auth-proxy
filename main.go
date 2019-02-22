package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/fatih/color"
	"github.com/kubernetes-sigs/aws-iam-authenticator/pkg/token"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
)

var (
	// ErrNameNotProvided is thrown when a name is not provided
	ErrNameNotProvided = errors.New("no name was provided in the HTTP body")
)

var gen token.Generator
var serviceMap map[string]string

var authDomain string
var authPort string

func secHeaders(w http.ResponseWriter) {
	w.Header().Set("content-security-policy", "script-src 'self'")
	w.Header().Set("x-xss-protection", "1; mode=block")
	w.Header().Set("x-frame-options", "SAMEORIGIN")
	w.Header().Set("x-content-type", "nosniff")
}

func validate(w http.ResponseWriter, r *http.Request) {
	log.Debugf("/validate from %s", r.RemoteAddr)

	cookiename := os.Getenv("COOKIE_NAME")
	if cookiename == "" {
		cookiename = "eks-auth"
	}
	// if we don't have the cookie, we are unauthorized.
	c, err := r.Cookie(cookiename)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		log.Debugf("%s is unauthorized", r.RemoteAddr)
		return
	}
	w.Header().Set("Authorization", fmt.Sprintf("Bearer %s", c.Value))
}

func signin(w http.ResponseWriter, r *http.Request) {
	var err error

	var redirect = r.URL.Query().Get("return")
	if redirect == "" {
		fmt.Fprintf(w, "No redirect specified")
		return
	}
	hostname := strings.Split(r.Host, ":")[0]

	var clusterID string
	var ok bool
	if clusterID, ok = serviceMap[redirect]; !ok {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, "Redirect is not in service map for any cluster")
		return
	}
	expectedHostname := viper.GetString(fmt.Sprintf("ressources.%s.my-hostname", clusterID))
	if expectedHostname != hostname {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, "Hostname %s is not expected.", hostname)
		return
	}

	log.Infof("Redirecting to %s", redirect)

	awsProfile := viper.GetString(fmt.Sprintf("ressources.%s.aws-profile", clusterID))
	if awsProfile != "" {
		log.Infof("Setting AWS_PROFILE to %s", awsProfile)
		os.Setenv("AWS_PROFILE", awsProfile)
	}

	var tok token.Token
	tok, err = gen.Get(clusterID)
	if err != nil {
		fmt.Fprintf(w, "Failed to retrieve token: %v", err)
		return
	}

	cookieDomain := viper.GetString(fmt.Sprintf("ressources.%s.cookie-domain", clusterID))
	if cookieDomain == "" {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "cookie domain is unset!")
		return
	}

	cookieName := viper.GetString(fmt.Sprintf("ressources.%s.cookie-name", clusterID))
	if cookieName == "" {
		cookieName = "eks-auth"
	}

	cookie := http.Cookie{Name: cookieName, Value: tok.Token, Expires: tok.Expiration, Domain: cookieDomain}
	http.SetCookie(w, &cookie)
	log.Print(redirect)
	secHeaders(w)
	http.Redirect(w, r, redirect, 302)

	log.Printf("Got token valid until %v", tok.Expiration)
}

func info(w http.ResponseWriter, r *http.Request) {
	secHeaders(w)
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprint(w, "Check startup message for configured clusters")
}

func updateClusters() {
	serviceMap = make(map[string]string)

	ressources := viper.GetStringMap("ressources")
	if len(ressources) == 0 {
		log.Warn("No ressources are configured.")
		return
	}
	log.Info("The following ressources are configured:")
	keys := make([]string, 0, len(ressources))
	for k := range ressources {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, cluster := range keys {
		data := viper.GetStringSlice(fmt.Sprintf("ressources.%s.services", cluster))
		for _, service := range data {
			log.Infof(" * %s (%s)\n", cluster, service)
			serviceMap[service] = cluster
		}
	}
}

var cfgFile string
var authEnabled = true

func initConfig() {
	home, err := homedir.Dir()
	if err != nil {
		log.Fatalf(color.RedString("Error getting home directory: %v"), err)
	}

	viper.SetConfigType("yaml")
	viper.AddConfigPath(home)
	viper.SetConfigName(".iam-auth-proxy")

	if err := viper.ReadInConfig(); err != nil {
		// we have no configuration for clusters, let's be safe and disable the /signin endpoint
		// the assumption is we're running on the cluster to do the redirecting part only.
		log.Infof("Can't read config: %v", err)
		log.Info("No config, disabling /signin endpoint")
		authEnabled = false
		return
	}
	updateClusters()
}

func init() {
	var err error
	initConfig()
	gen, err = token.NewGenerator(true)

	if err != nil {
		log.Fatalf("Failed to start service: %v", err)
	}
}

func main() {
	log.SetLevel(log.DebugLevel)

	http.HandleFunc("/", info)
	http.HandleFunc("/validate", validate)

	var listen = "0.0.0.0"
	if authEnabled {
		// if we can authenticate, we should not listen on external IPs! Otherwise credenials
		// might be extracted over the network
		listen = "127.0.0.1"
		http.HandleFunc("/signin", signin)
	}
	log.Info(fmt.Sprintf("Listening on %s:8080", listen))
	http.ListenAndServe(fmt.Sprintf("%s:8080", listen), nil)
}
