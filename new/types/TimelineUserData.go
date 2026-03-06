package types

type TimelineUserData struct {
	PageTitle   string
	PageID      string // "public", "timeline", or "user"
	Messages    []Message
	ProfileUser *User // The user whose profile we are viewing (can be nil)
	CurrentUser *User // The user currently logged in (can be nil)
	IsFollowing bool
	Flashes     []string
	Page        int // Current page number
	NextPage    int // Next page number (-1 if no next)
	PrevPage    int // Previous page number (-1 if no prev)
}
