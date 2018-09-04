package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"runtime"

	oidc "github.com/coreos/go-oidc"

	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

const (
	// NOTE: don't update these constants, kubernetes client-go uses them refresh oidc token,
	// but those constants are lowercase and cannot be referenced.
	cfgIssuerURL    = "idp-issuer-url"
	cfgClientID     = "client-id"
	cfgClientSecret = "client-secret"
	cfgIDToken      = "id-token"
	cfgRefreshToken = "refresh-token"
	// state usually used for client verifies the token returned by the authentication server.
	state = "hello world"
)

// we will open the default browser on different systems to get the token.
var commands = map[string]string{
	"windows": "cmd /c start",
	"darwin":  "open",
	"linux":   "xdg-open",
}

var (
	kubeConfigPath string
)

func main() {
	cmd := &cobra.Command{
		Use:   "login",
		Short: "kubectl command line plugin",
		Long:  `mv kubectl-login to /user/local/bin/, then you can kubectl login call this command.`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := login(cmd, args); err != nil {
				log.Fatal(err)
			}
		},
	}
	cmd.Flags().StringVar(&kubeConfigPath, "kubeconfig", "", "path to kubeconfig")

	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func login(cmd *cobra.Command, args []string) error {
	pathOption := clientcmd.NewDefaultPathOptions()
	pathOption.LoadingRules.ExplicitPath = kubeConfigPath
	apiConfig, err := pathOption.GetStartingConfig()
	if err != nil {
		return err
	}

	c, ok := apiConfig.Contexts[apiConfig.CurrentContext]
	if !ok {
		return fmt.Errorf("unable get current context")
	}
	config, ok := apiConfig.AuthInfos[c.AuthInfo]
	if !ok {
		return fmt.Errorf("unable get current auth info")
	}
	if config.AuthProvider == nil || config.AuthProvider.Name != "oidc" {
		return fmt.Errorf("only support oidc login flow")
	}
	issuer, ok := config.AuthProvider.Config[cfgIssuerURL]
	if !ok {
		return fmt.Errorf("must special %s value in oidc auth provider config", cfgIssuerURL)
	}
	clientID, ok := config.AuthProvider.Config[cfgClientID]
	if !ok {
		return fmt.Errorf("must special %s value in oidc auth provider config", cfgClientID)
	}
	clientSecret, ok := config.AuthProvider.Config[cfgClientSecret]
	if !ok {
		return fmt.Errorf("must special %s value in oidc auth provider config", cfgClientSecret)
	}
	// TODO: support https
	httpClient := &http.Client{}
	ctx := oidc.ClientContext(context.Background(), httpClient)

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return fmt.Errorf("failed to query provider %q: %v", issuer, err)
	}

	oauthConfig := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "http://localhost:8080/callback",
		Scopes:       []string{"openid", "profile", "offline_access"},
	}

	closeCh := make(chan bool)
	defer close(closeCh)
	// note: must use non-blocking channel, otherwise it will always be block.
	refleshTokenCh := make(chan string, 1)
	defer close(refleshTokenCh)
	idTokenCh := make(chan string, 1)
	defer close(idTokenCh)

	oidc := OIDC{
		clientID:     clientID,
		oauthConfig:  oauthConfig,
		provider:     provider,
		client:       httpClient,
		configAccess: pathOption,
		AuthProvider: config.AuthProvider,
		config:       apiConfig,
		refleshToken: refleshTokenCh,
		idToken:      idTokenCh,
	}

	http.HandleFunc("/callback", oidc.handleCallback)
	go http.ListenAndServe("localhost:8080", nil)
	// oauth2.SetAuthURLParam("prompt", "consent") used for get reflesh token.
	URL := oauthConfig.AuthCodeURL(state, oauth2.SetAuthURLParam("prompt", "consent"))
	if err := Open(URL); err != nil {
		return err
	}

	go oidc.updateKubeConfig(closeCh)

	<-closeCh
	return nil
}

// Open calls the OS default program for uri
func Open(uri string) error {
	run, ok := commands[runtime.GOOS]
	if !ok {
		return fmt.Errorf("don't know how to open things on %s platform", runtime.GOOS)
	}
	cmd := exec.Command(run, uri)
	return cmd.Start()
}

type OIDC struct {
	clientID     string
	oauthConfig  oauth2.Config
	provider     *oidc.Provider
	client       *http.Client
	configAccess clientcmd.ConfigAccess
	config       *api.Config
	AuthProvider *api.AuthProviderConfig
	refleshToken chan string
	idToken      chan string
}

func (o *OIDC) handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	if code == "" {
		http.Error(w, fmt.Sprintf("no code in request: %q", r.Form), http.StatusBadRequest)
		return
	}
	if resState := r.FormValue("state"); resState != state {
		http.Error(w, fmt.Sprintf("expected state %q got %q", state, resState), http.StatusBadRequest)
		return
	}

	ctx := oidc.ClientContext(r.Context(), o.client)
	token, err := o.oauthConfig.Exchange(ctx, code)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to exchange token: %v", err), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token in token response", http.StatusInternalServerError)
		return
	}

	verify := o.provider.Verifier(&oidc.Config{ClientID: o.clientID})
	IDtoken, err := verify.Verify(r.Context(), rawIDToken)
	if !ok {
		http.Error(w, "failed verify IDToken", http.StatusInternalServerError)
		return
	}
	http.ResponseWriter.Write(w, []byte(fmt.Sprintf("%s login success", IDtoken.Subject)))

	// this code needs to be placed under response, otherwise the terminal will succeed,
	// but the web does not show login success.
	o.refleshToken <- token.RefreshToken
	o.idToken <- rawIDToken
}

func (o *OIDC) updateKubeConfig(closeCh chan bool) {
	o.AuthProvider.Config[cfgIDToken] = <-o.idToken
	o.AuthProvider.Config[cfgRefreshToken] = <-o.refleshToken
	c := o.config.Contexts[o.config.CurrentContext]
	o.config.AuthInfos[c.AuthInfo] = &api.AuthInfo{
		AuthProvider: o.AuthProvider,
	}
	clientcmd.ModifyConfig(o.configAccess, *o.config, true)

	closeCh <- true
}
