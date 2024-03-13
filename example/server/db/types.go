package db

type Account struct {
	ClientID string `json:"clientID,omitempty"`
	Name     string
	Money    int
}
