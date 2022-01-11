package structures

type Credentials struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type ErrorResponse struct {
	Err interface{} `json:"error"`
}

type ListItem struct {
	Path  string `json:"path"`
	IsDir bool   `json:"is_dir"`
}
