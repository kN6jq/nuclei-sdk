package http

// ResponseData holds parsed HTTP response data for matcher evaluation.
type ResponseData struct {
	StatusCode  int
	Body        string
	Headers     string
	ContentType string
	Title       string
	Cookies     string
	Duration    float64
	All         string
}