package main

import (
	"encoding/json"
	"flag"
	"io"

	"fmt"
	"log"
	"net/http"
	"os"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/federation"

	"codeberg.org/plate/uwuserv/util"
)

type Server struct {
	ServerName string
	Client     *federation.Client
	PolicyKey  federation.SigningKey
}

type Config struct {
	ServerName    string `json:"server_name"`
	FederationKey string `json:"federation_key"`
	PolicyKey     string `json:"policy_key"`
	ListenAddress string `json:"listen_address"`
}

func (s *Server) Sign(w http.ResponseWriter, r *http.Request) {
	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		mautrix.MUnknown.Write(w)
		return
	}
	// unmarshal
	// TODO: use a more specific type
	var content json.RawMessage
	err = json.Unmarshal(reqBody, &content)
	if err != nil {
		mautrix.MNotJSON.Write(w)
		return
	}
	// check
	ok := util.Check(content, s.ServerName)
	if !ok {
		mautrix.MForbidden.Write(w)
		return
	}
	// sign the json
	signed, err := util.Sign(s.PolicyKey, s.Client.ServerName, content)
	if err != nil {
		mautrix.MUnknown.Write(w)
		return
	}
	// serve
	signedJSON, err := json.Marshal(&signed)
	if err != nil {
		mautrix.MUnknown.Write(w)
		return
	}
	w.Header().Add("content-type", "application/json")
	w.Write(signedJSON)
}

func main() {
	var configFile string
	var generateConfig bool

	flag.StringVar(&configFile, "config", "config.json", "Config path")
	flag.BoolVar(&generateConfig, "generate", false, "Generate config")
	flag.Parse()

	if generateConfig {
		policyKey := federation.GenerateSigningKey()
		policyKey.ID = "policy_server"
		config := &Config{
			ServerName:    "hostname.here",
			FederationKey: federation.GenerateSigningKey().SynapseString(),
			PolicyKey:     policyKey.SynapseString(),
			ListenAddress: "localhost:8089",
		}
		bytes, err := json.Marshal(&config)
		if err != nil {
			log.Fatal(err)
		}
		err = os.WriteFile(configFile, bytes, 0640)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Generated config")
		os.Exit(0)
	}

	file, err := os.Open(configFile)
	if err != nil {
		log.Fatal(err)
	}
	config := Config{}
	bytes, err := io.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}
	err = json.Unmarshal(bytes, &config)
	if err != nil {
		log.Fatal(err)
	}

	fedKey, err := federation.ParseSynapseKey(config.FederationKey)
	if err != nil {
		log.Fatal(err)
	}
	policyKey, err := federation.ParseSynapseKey(config.PolicyKey)
	if err != nil {
		log.Fatal(err)
	}
	cache := federation.NewInMemoryCache()
	client := federation.NewClient(config.ServerName, fedKey, cache)
	server := Server{
		ServerName: config.ServerName,
		PolicyKey:  *policyKey,
		Client:     client,
	}
	keyServer := federation.KeyServer{
		KeyProvider: &federation.StaticServerKey{
			ServerName: config.ServerName,
			Key:        fedKey,
		},
		Version: federation.ServerVersion{
			Name:    "uwuserv",
			Version: "0.1.0",
		},
	}
	http.HandleFunc("POST /_matrix/policy/v1/sign", server.Sign)
	http.HandleFunc("/_matrix/key/v2/server", keyServer.GetServerKey)
	http.HandleFunc("/_matrix/federation/v1/version", keyServer.GetServerVersion)
	log.Print("Listening on ", config.ListenAddress)
	log.Fatal(http.ListenAndServe(config.ListenAddress, nil))
}
