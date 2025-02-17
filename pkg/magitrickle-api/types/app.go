package types

type NetfilterDHookReq struct {
	Type  string `json:"type"`
	Table string `json:"table"`
}
