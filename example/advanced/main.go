package main

import (
	"html/template"
	"log"
	"net/http"
	"sync"

	"github.com/mnehpets/http/auth"
	"github.com/mnehpets/http/endpoint"
	"github.com/mnehpets/http/middleware"
)

var (
	msgMu    sync.RWMutex
	msgStore = make(map[string][]string)
)

// LoginEndpoint handles user login.
func LoginEndpoint(_ http.ResponseWriter, r *http.Request, params struct {
	Email string `form:"email"`
}) (endpoint.Renderer, error) {
	sess, ok := middleware.SessionFromContext(r.Context())
	if !ok {
		return nil, endpoint.Error(http.StatusInternalServerError, "no session", nil)
	}
	if params.Email == "" {
		return nil, endpoint.Error(http.StatusBadRequest, "email required", nil)
	}

	if err := sess.Login(params.Email); err != nil {
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
// It is protected by requireExampleCom, so sess.Username() is guaranteed to
// return a logged-in @example.com address by the time this runs.
func SendEndpoint(_ http.ResponseWriter, r *http.Request, params struct {
	TargetUser string `form:"username"`
	Message    string `form:"msg"`
}) (endpoint.Renderer, error) {
	sess, _ := middleware.SessionFromContext(r.Context())
	sender, _ := sess.Username()
	msgMu.Lock()
	msgStore[params.TargetUser] = append(msgStore[params.TargetUser], sender+": "+params.Message)
	msgMu.Unlock()
	return &endpoint.RedirectRenderer{URL: "/messages", Status: http.StatusSeeOther}, nil
}

var unauthorizedTmpl = template.Must(template.New("unauthorized").Parse(`
<!DOCTYPE html>
<html>
<head><title>Unauthorized</title></head>
<body>
	<h1>Unauthorized</h1>
	<p>Sending messages requires an @example.com email address.</p>
	<p><a href="/messages">Back</a></p>
</body>
</html>
`))

// UnauthorizedEndpoint is shown when the authz processor rejects a request.
func UnauthorizedEndpoint(_ http.ResponseWriter, _ *http.Request, _ struct{}) (endpoint.Renderer, error) {
	return &endpoint.HTMLTemplateRenderer{
		Template: unauthorizedTmpl,
		Status:   http.StatusForbidden,
	}, nil
}

var msgTmpl = template.Must(template.New("messages").Parse(`
<!DOCTYPE html>
<html>
<head>
	<title>Messages</title>
</head>
<body>
	<h1>OneServe Messages</h1>
	{{if .Email}}
		<p>Logged in as {{.Email}}</p>
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
		<p>Sending messages requires an @example.com email address.</p>
		<form action="/login" method="post">
			<label>Email: <input type="email" name="email" required></label><br>
			<button type="submit">Login</button>
		</form>
	{{end}}
</body>
</html>
`))

// MessagesEndpoint retrieves messages for the logged-in user.
func MessagesEndpoint(_ http.ResponseWriter, r *http.Request, _ struct{}) (endpoint.Renderer, error) {
	email := ""
	sess, ok := middleware.SessionFromContext(r.Context())
	if ok {
		email, _ = sess.Username()
	}

	var msgs []string
	if email != "" {
		msgMu.RLock()
		msgs = msgStore[email]
		msgMu.RUnlock()
	}

	return &endpoint.HTMLTemplateRenderer{
		Template: msgTmpl,
		Values: map[string]any{
			"Email":    email,
			"Messages": msgs,
		},
	}, nil
}

func main() {
	var err error

	// Create the session middleware.
	sessionProcessor, err := middleware.NewSessionProcessor(
		"1",
		map[string][]byte{
			"1": []byte("0123456789ABCDEF0123456789ABCDEF"),
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	// Restrict sending to @example.com addresses.
	allowExampleCom, err := auth.MatchEmailGlob([]string{"*@example.com"})
	if err != nil {
		log.Fatal(err)
	}

	// onFailure redirects to the unauthorized page.
	onFailure := func(w http.ResponseWriter, r *http.Request) (endpoint.Renderer, error) {
		return &endpoint.RedirectRenderer{URL: "/unauthorized", Status: http.StatusSeeOther}, nil
	}

	requireExampleCom, err := auth.NewRequireUsernameMatchProcessor(allowExampleCom, onFailure)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()

	mux.Handle("GET /unauthorized", endpoint.HandleFunc(UnauthorizedEndpoint))
	mux.Handle("POST /login", endpoint.HandleFunc(LoginEndpoint, sessionProcessor))
	mux.Handle("POST /logout", endpoint.HandleFunc(LogoutEndpoint, sessionProcessor))
	mux.Handle("POST /send", endpoint.HandleFunc(SendEndpoint, sessionProcessor, requireExampleCom))
	mux.Handle("GET /messages", endpoint.HandleFunc(MessagesEndpoint, sessionProcessor))
	mux.Handle("/", http.RedirectHandler("/messages", http.StatusTemporaryRedirect))

	log.Println("Listening on :8080")

	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal(err)
	}
}
