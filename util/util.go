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
	AuthEvents     []id.EventID                   `json:"auth_events"`
	Content        json.RawMessage                `json:"content"`
	Depth          int                            `json:"depth"`
	Hashes         json.RawMessage                `json:"hashes"`
	OriginServerTS int                            `json:"origin_server_ts"`
	PrevEvents     []id.EventID                   `json:"prev_events"`
	RoomID         id.RoomID                      `json:"room_id"`
	Sender         id.UserID                      `json:"sender"`
	Signatures     map[string]map[id.KeyID]string `json:"signatures"`
	Type           string                         `json:"type"`
	Unsigned       json.RawMessage                `json:"unsigned"`
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

func Sign(key federation.SigningKey, serverName string, content json.RawMessage) (map[id.KeyID]string, error) {
	// don't you need to use the redaction algorithm before signing?
	// maybe delete signatures from a copy of the map
	sig, err := key.SignJSON(content)
	if err != nil {
		return nil, err
	}
	return map[id.KeyID]string{key.ID: sig}, nil
}
