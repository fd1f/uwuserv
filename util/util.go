package util

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"

	"maunium.net/go/mautrix/crypto/canonicaljson"
	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/id"
)

type ParsedPDU struct {
	// TODO: rest of the fields. currently i have enough to be useful
	Content        json.RawMessage                `json:"content"`
	Sender         id.UserID                      `json:"sender"`
	Signatures     map[string]map[id.KeyID]string `json:"signatures"`
	OriginServerTS int32                          `json:"origin_server_ts"`
}

func Hash(data any) string {
	var contentBytes []byte
	var sum []byte
	json.Unmarshal(contentBytes, &data)
	canonicalised, _ := canonicaljson.CanonicalJSON(contentBytes)
	// if there's a better way i want to know immediately. i wrote this while offline,
	// i can't encode the [32]byte value Sum256 returns :(
	for _, v := range sha256.Sum256(canonicalised) {
		sum = append(sum, v)
	}
	return base64.RawStdEncoding.EncodeToString(sum)
}

func Sign(key federation.SigningKey, serverName string, content json.RawMessage) (json.RawMessage, error) {
	// unmarshal
	// contentJSON, _ := json.Marshal(&content)
	// sign and return
	var parsedContent ParsedPDU
	// don't you need to use the redaction algorithm before signing?
	// maybe delete signatures from a copy of the map
	sig, _ := key.SignJSON(content)
	json.Unmarshal(content, &parsedContent)
	parsedContent.Signatures[serverName] = map[id.KeyID]string{
		key.ID: sig,
	}
	finalContent, err := json.Marshal(parsedContent)
	if err != nil {
		return nil, err
	}
	return finalContent, nil
}
