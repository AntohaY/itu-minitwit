package types

type BaseContext struct {
	User    *User    // Wraps the current user (replaces g.user)
	Flashes []string // Replaces get_flashed_messages()
}
