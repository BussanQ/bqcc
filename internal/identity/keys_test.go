package identity

import "testing"

func TestUnmarshalSignedStateNormalizesCreateProfileAttributes(t *testing.T) {
	data := []byte(`{
  "document": {
    "id": "did:p2p:test",
    "version": "2"
  },
  "events": [
    {
      "id": "evt1",
      "type": "CreateIdentity",
      "identityId": "did:p2p:test",
      "signerKeyId": "root",
      "timestamp": "2026-04-08T17:53:40Z",
      "payload": {
        "profile": {
          "displayName": "alice",
          "bio": "",
          "attributes": {}
        }
      },
      "signature": "sig"
    }
  ]
}`)
	state, err := UnmarshalSignedState(data)
	if err != nil {
		t.Fatalf("unmarshal signed state: %v", err)
	}
	profile, ok := state.Events[0].Payload["profile"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected profile payload map")
	}
	attributes, ok := profile["attributes"].(map[string]string)
	if !ok {
		t.Fatalf("expected normalized attributes map[string]string, got %T", profile["attributes"])
	}
	if len(attributes) != 0 {
		t.Fatalf("expected empty attributes")
	}
}

func TestUnmarshalLocalNormalizesCreateProfileAttributes(t *testing.T) {
	data := []byte(`{
  "document": {
    "id": "did:p2p:test",
    "version": "2"
  },
  "events": [
    {
      "id": "evt1",
      "type": "CreateIdentity",
      "identityId": "did:p2p:test",
      "signerKeyId": "root",
      "timestamp": "2026-04-08T17:53:40Z",
      "payload": {
        "profile": {
          "displayName": "alice",
          "bio": "",
          "attributes": {}
        }
      },
      "signature": "sig"
    }
  ],
  "localKeys": []
}`)
	local, err := UnmarshalLocal(data)
	if err != nil {
		t.Fatalf("unmarshal local identity: %v", err)
	}
	profile, ok := local.Events[0].Payload["profile"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected profile payload map")
	}
	attributes, ok := profile["attributes"].(map[string]string)
	if !ok {
		t.Fatalf("expected normalized attributes map[string]string, got %T", profile["attributes"])
	}
	if len(attributes) != 0 {
		t.Fatalf("expected empty attributes")
	}
}
