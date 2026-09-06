package notify

type Message struct {
	To      []string
	Subject string
	Body    string
	Data    map[string]any
}
