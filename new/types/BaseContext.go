package types

import "minitwit/domains"

type BaseContext struct {
	User    *domains.User // Wraps the current user (replaces g.user)
	Flashes []string      // Replaces get_flashed_messages()
}
