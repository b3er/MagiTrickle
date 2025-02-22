package types

type GroupsReq struct {
	Groups *[]GroupReq `json:"groups"`
}

type GroupsRes struct {
	Groups *[]GroupRes `json:"groups,omitempty"`
}

type GroupReq struct {
	ID         *ID    `json:"id" example:"0a1b2c3d" swaggertype:"string"`
	Name       string `json:"name" example:"Routing"`
	Interface  string `json:"interface" example:"nwg0"`
	FixProtect bool   `json:"fixProtect" example:"false"`
	RulesReq
}

type GroupRes struct {
	ID         ID     `json:"id" example:"0a1b2c3d" swaggertype:"string"`
	Name       string `json:"name" example:"Routing"`
	Interface  string `json:"interface" example:"nwg0"`
	FixProtect bool   `json:"fixProtect" example:"false"`
	RulesRes
}
