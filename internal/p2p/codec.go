package p2p

import (
	"encoding/json"

	"github.com/example/decentid/pkg/types"
)

func marshalState(state types.SignedIdentityState) ([]byte, error) {
	return json.Marshal(state)
}

func unmarshalState(data []byte) (types.SignedIdentityState, error) {
	var state types.SignedIdentityState
	err := json.Unmarshal(data, &state)
	return state, err
}
