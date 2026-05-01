package types

type BaseContext struct {
	CurrentUser *User    // Wraps the current user (replaces g.user)
	Flashes     []string // Replaces get_flashed_messages()
	PageTitle   string
}
