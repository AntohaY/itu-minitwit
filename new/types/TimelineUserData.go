package types

import "minitwit/domains"

type TimelineUserData struct {
	PageTitle    string
	PageID       string // "public", "timeline", or "user"
	Messages     []Message
	ProfileUser  *domains.User // The user whose profile we are viewing (can be nil)
	CurrentUser  *domains.User // The user currently logged in (can be nil)
	IsFollowing  bool
	Flashes      []string
	Page         int // Current page number
	NextPage     int // Next page number (-1 if no next)
	PrevPage     int // Previous page number (-1 if no prev)
	TotalPages   int
	VisiblePages []int
}
