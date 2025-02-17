package types

import (
	"encoding/hex"
)

type ID [4]byte

func (id *ID) String() string {
	return hex.EncodeToString(id[:])
}

func (id *ID) MarshalText() ([]byte, error) {
	return []byte(id.String()), nil
}

func (id *ID) UnmarshalText(data []byte) error {
	_, err := hex.Decode(id[:], data)
	return err
}
