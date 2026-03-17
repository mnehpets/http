package main

import (
	"html/template"
	"log"
	"net/http"
	"sync"

	"github.com/mnehpets/http/endpoint"
	"github.com/mnehpets/http/middleware"
)

var (
	msgMu    sync.RWMutex
	msgStore = make(map[string][]string)
)

// LoginEndpoint handles user login.
func LoginEndpoint(_ http.ResponseWriter, r *http.Request, params struct {
	Username string `form:"username"`
}) (endpoint.Renderer, error) {
	sess, ok := middleware.SessionFromContext(r.Context())
	if !ok {
		return nil, endpoint.Error(http.StatusInternalServerError, "no session", nil)
	}
	if params.Username == "" {
		return nil, endpoint.Error(http.StatusBadRequest, "username required", nil)
	}

	// Login the user.
	if err := sess.Login(params.Username); err != nil {
		return nil, endpoint.Error(http.StatusInternalServerError, err.Error(), err)
	}
	return &endpoint.RedirectRenderer{URL: "/messages", Status: http.StatusSeeOther}, nil
}

// LogoutEndpoint handles user logout.
func LogoutEndpoint(_ http.ResponseWriter, r *http.Request, _ struct{}) (endpoint.Renderer, error) {
	sess, ok := middleware.SessionFromContext(r.Context())
	if ok {
		sess.Logout()
	}
	return &endpoint.RedirectRenderer{URL: "/messages", Status: http.StatusSeeOther}, nil
}

// SendEndpoint sends a message to a user.
func SendEndpoint(_ http.ResponseWriter, r *http.Request, params struct {
	TargetUser string `form:"username"`
	Message    string `form:"msg"`
}) (endpoint.Renderer, error) {
	sess, ok := middleware.SessionFromContext(r.Context())
	if !ok {
		return nil, endpoint.Error(http.StatusInternalServerError, "no session", nil)
	}
	username, _ := sess.Username()
	msgMu.Lock()
	msgStore[params.TargetUser] = append(msgStore[params.TargetUser], username+": "+params.Message)
	msgMu.Unlock()
	return &endpoint.RedirectRenderer{URL: "/messages", Status: http.StatusSeeOther}, nil
}

var msgTmpl = template.Must(template.New("messages").Parse(`
<!DOCTYPE html>
<html>
<head>
	<title>Messages</title>
</head>
<body>
	<h1>OneServe Messages</h1>
	{{if .Username}}
		<p>Logged in as {{.Username}}</p>
		<form action="/logout" method="post">
			<button type="submit">Logout</button>
		</form>

		<h2>Messages</h2>

		{{range .Messages}}
			{{.}}<br/>
		{{else}}
			<li>No messages.</li>
		{{end}}

		<h2>Send Message</h2>
		<form action="/send" method="post">
			<label>To: <input type="text" name="username" required></label><br>
			<label>Message: <input type="text" name="msg" required></label><br>
			<button type="submit">Send</button>
		</form>
	{{else}}
		<h2>Login</h2>
		<form action="/login" method="post">
			<label>Username: <input type="text" name="username" required></label><br>
			<button type="submit">Login</button>
		</form>
	{{end}}
</body>
</html>
`))

// MessagesEndpoint retrieves messages for the logged-in user.
func MessagesEndpoint(_ http.ResponseWriter, r *http.Request, _ struct{}) (endpoint.Renderer, error) {
	username := ""
	sess, ok := middleware.SessionFromContext(r.Context())
	if ok {
		username, _ = sess.Username()
	}

	var msgs []string
	if username != "" {
		msgMu.RLock()
		msgs = msgStore[username]
		msgMu.RUnlock()
	}

	return &endpoint.HTMLTemplateRenderer{
		Template: msgTmpl,
		Values: map[string]any{
			"Username": username,
			"Messages": msgs,
		},
	}, nil
}

func main() {
	var err error

	// Create the session middleware.
	sessionProcessor, err := middleware.NewSessionProcessor(
		"1", // Key ID
		map[string][]byte{
			"1": []byte("0123456789ABCDEF0123456789ABCDEF"), // 32-byte key for chacha20poly1305
		}, // Keys
	)
	if err != nil {
		log.Fatal(err)
	}

	// Create a new ServeMux.
	mux := http.NewServeMux()

	// Register the endpoints.
	// endpoint.HandleFunc wraps the function with parameter decoding and error handling.

	// New endpoints
	mux.Handle("POST /login", endpoint.HandleFunc(LoginEndpoint, sessionProcessor))
	mux.Handle("POST /logout", endpoint.HandleFunc(LogoutEndpoint, sessionProcessor))
	mux.Handle("POST /send", endpoint.HandleFunc(SendEndpoint, sessionProcessor))
	mux.Handle("GET /messages", endpoint.HandleFunc(MessagesEndpoint, sessionProcessor))
	mux.Handle("/", http.RedirectHandler("/messages", http.StatusTemporaryRedirect))

	log.Println("Listening on :8080")

	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal(err)
	}
}
