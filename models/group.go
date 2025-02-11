package models

type Group struct {
	ID         [4]byte
	Name       string
	Interface  string
	Rules      []*Rule
	FixProtect bool
}
