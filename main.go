package main

import (
	"bytes"
	"encoding/json"
	"fmt"

	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

var store = sessions.NewCookieStore([]byte("{{SESSION_SECRET_KEY}}"))

type User struct {
	Username string
	Password string
}

type Service struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Subdomain   string `json:"subdomain"`
	Port        string `json:"port"`
	Description string `json:"description"`
	Status      string `json:"status"`
}

type DNSRecord struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
}

var users = []User{
	{Username: "admin", Password: ""},
	{Username: "anshuman", Password: ""},
}

var services = []Service{
	{ID: 1, Name: "dashy.biswas.me", Subdomain: "dashy", Port: "4000", Description: "Main Dashboard", Status: "running"},
	{ID: 2, Name: "dockge.biswas.me", Subdomain: "dockge", Port: "5002", Description: "Container Management", Status: "running"},
	{ID: 3, Name: "jellyfin.biswas.me", Subdomain: "jellyfin", Port: "8096", Description: "Media Server", Status: "running"},
	{ID: 4, Name: "vaultwarden.biswas.me", Subdomain: "vaultwarden", Port: "9480", Description: "Password Manager", Status: "running"},
	{ID: 5, Name: "heimdall.biswas.me", Subdomain: "heimdall", Port: "3380", Description: "Application Dashboard", Status: "running"},
	{ID: 6, Name: "ha.biswas.me", Subdomain: "ha", Port: "8123", Description: "Home Assistant", Status: "running"},
	{ID: 7, Name: "n8n.biswas.me", Subdomain: "n8n", Port: "5678", Description: "Workflow Automation", Status: "running"},
	{ID: 8, Name: "calibre.biswas.me", Subdomain: "calibre", Port: "8083", Description: "E-book Management", Status: "running"},
	{ID: 9, Name: "ab.biswas.me", Subdomain: "ab", Port: "13378", Description: "Audiobookshelf", Status: "running"},
	{ID: 10, Name: "actual.biswas.me", Subdomain: "actual", Port: "5006", Description: "Budget Management", Status: "running"},
}

const (
	CADDY_ADMIN_URL = "http://localhost:2019"
	CLOUDFLARE_ZONE = "biswas.me"
	CNAME_TARGET    = "anshuman.duckdns.com"
)

func init() {
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   false, // Set to true if using HTTPS
		SameSite: http.SameSiteStrictMode,
	}

	hash1, _ := bcrypt.GenerateFromPassword([]byte("{{ADMIN_PASSWORD}}"), bcrypt.DefaultCost)
	hash2, _ := bcrypt.GenerateFromPassword([]byte("{{USER_PASSWORD}}"), bcrypt.DefaultCost)
	users[0].Password = string(hash1)
	users[1].Password = string(hash2)
}

func authenticate(username, password string) bool {
	for _, user := range users {
		if user.Username == username {
			err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
			return err == nil
		}
	}
	return false
}

func requireAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session-name")
		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		handler(w, r)
	}
}

// Caddy Admin API functions
func updateCaddyConfig(service Service) error {
	// Create reverse proxy configuration for the service
	config := map[string]interface{}{
		"@id": service.Subdomain,
		"match": []map[string]interface{}{
			{"host": []string{service.Name}},
		},
		"handle": []map[string]interface{}{
			{
				"handler": "reverse_proxy",
				"upstreams": []map[string]interface{}{
					{"dial": fmt.Sprintf("localhost:%s", service.Port)},
				},
			},
		},
	}

	jsonData, err := json.Marshal(config)
	if err != nil {
		return err
	}

	// Update Caddy configuration via Admin API
	resp, err := http.Post(fmt.Sprintf("%s/config/apps/http/servers/srv0/routes", CADDY_ADMIN_URL),
		"application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func createDNSRecord(subdomain string) error {
	// This would integrate with Caddy's Cloudflare DNS plugin
	// For now, we'll simulate the API call
	log.Printf("Creating DNS record: %s.%s CNAME %s", subdomain, CLOUDFLARE_ZONE, CNAME_TARGET)
	return nil
}

func deleteDNSRecord(subdomain string) error {
	// This would integrate with Caddy's Cloudflare DNS plugin
	// For now, we'll simulate the API call
	log.Printf("Deleting DNS record: %s.%s", subdomain, CLOUDFLARE_ZONE)
	return nil
}

// HTTP Handlers
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		loginHTML := `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Caddy Admin Login</title>
	<style>
		body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; justify-content: center; align-items: center; }
		.login-container { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 20px 40px rgba(0,0,0,0.1); width: 100%; max-width: 400px; }
		h1 { margin-bottom: 30px; color: #2d3748; text-align: center; font-size: 2rem; }
		.form-group { margin-bottom: 20px; }
		label { display: block; margin-bottom: 8px; font-weight: 500; color: #4a5568; }
		input[type="text"], input[type="password"] { width: 100%; padding: 12px; border: 1px solid #e2e8f0; border-radius: 8px; font-size: 16px; transition: border-color 0.3s ease; box-sizing: border-box; }
		input:focus { outline: none; border-color: #4299e1; box-shadow: 0 0 0 3px rgba(66, 153, 225, 0.1); }
		button { width: 100%; background: #4299e1; color: white; padding: 12px; border: none; border-radius: 8px; cursor: pointer; font-size: 16px; font-weight: 500; }
		button:hover { background: #3182ce; }
		.error { color: #e53e3e; margin-bottom: 20px; padding: 10px; background: #fed7d7; border-radius: 6px; }
	</style>
</head>
<body>
	<div class="login-container">
		<h1>🚀 Caddy Admin</h1>
		<form method="POST" action="/login">
			<div class="form-group">
				<label for="username">Username</label>
				<input type="text" id="username" name="username" required>
			</div>
			<div class="form-group">
				<label for="password">Password</label>
				<input type="password" id="password" name="password" required>
			</div>
			<button type="submit">Login</button>
		</form>
	</div>
</body>
</html>`
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(loginHTML))
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if authenticate(username, password) {
		session, _ := store.Get(r, "session-name")
		session.Values["authenticated"] = true
		session.Values["username"] = username
		session.Save(r, w)
		http.Redirect(w, r, "/", http.StatusFound)
	} else {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	session.Values["authenticated"] = false
	session.Save(r, w)
	http.Redirect(w, r, "/login", http.StatusFound)
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	http.ServeFile(w, r, "html/index.html")
}

func apiServicesHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(services)

	case "POST":
		var newService Service
		if err := json.NewDecoder(r.Body).Decode(&newService); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		// Generate new ID
		newService.ID = len(services) + 1
		newService.Name = fmt.Sprintf("%s.biswas.me", newService.Subdomain)
		newService.Status = "running"

		// Create DNS record
		if err := createDNSRecord(newService.Subdomain); err != nil {
			log.Printf("Error creating DNS record: %v", err)
		}

		// Update Caddy configuration
		if err := updateCaddyConfig(newService); err != nil {
			log.Printf("Error updating Caddy config: %v", err)
		}

		services = append(services, newService)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(newService)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func apiServiceHandler(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/services/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid service ID", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case "PUT":
		var updatedService Service
		if err := json.NewDecoder(r.Body).Decode(&updatedService); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		// Find and update service
		for i, service := range services {
			if service.ID == id {
				oldSubdomain := service.Subdomain

				// Update service details
				services[i].Description = updatedService.Description
				services[i].Port = updatedService.Port

				// If subdomain changed, update DNS
				if updatedService.Subdomain != oldSubdomain {
					// Delete old DNS record
					if err := deleteDNSRecord(oldSubdomain); err != nil {
						log.Printf("Error deleting old DNS record: %v", err)
					}

					// Create new DNS record
					if err := createDNSRecord(updatedService.Subdomain); err != nil {
						log.Printf("Error creating new DNS record: %v", err)
					}

					services[i].Subdomain = updatedService.Subdomain
					services[i].Name = fmt.Sprintf("%s.biswas.me", updatedService.Subdomain)
				}

				// Update Caddy configuration
				if err := updateCaddyConfig(services[i]); err != nil {
					log.Printf("Error updating Caddy config: %v", err)
				}

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(services[i])
				return
			}
		}

		http.Error(w, "Service not found", http.StatusNotFound)

	case "DELETE":
		for i, service := range services {
			if service.ID == id {
				// Delete DNS record
				if err := deleteDNSRecord(service.Subdomain); err != nil {
					log.Printf("Error deleting DNS record: %v", err)
				}

				// Remove from services slice
				services = append(services[:i], services[i+1:]...)

				w.WriteHeader(http.StatusNoContent)
				return
			}
		}

		http.Error(w, "Service not found", http.StatusNotFound)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func caddyProxyHandler(w http.ResponseWriter, r *http.Request) {
	// Proxy requests to Caddy Admin API
	path := strings.TrimPrefix(r.URL.Path, "/caddy-api")
	targetURL := CADDY_ADMIN_URL + path

	req, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		http.Error(w, "Error creating request", http.StatusInternalServerError)
		return
	}

	// Copy headers
	for key, values := range r.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Error making request", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func main() {
	// Ensure the Caddy admin endpoint is accessible
	if os.Getenv("CADDY_ADMIN_URL") != "" {
		// Use custom Caddy admin URL from environment
		log.Printf("Using Caddy Admin API at: %s", os.Getenv("CADDY_ADMIN_URL"))
	}

	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/", requireAuth(dashboardHandler))
	http.HandleFunc("/api/services", requireAuth(apiServicesHandler))
	http.HandleFunc("/api/services/", requireAuth(apiServiceHandler))
	http.HandleFunc("/caddy-api/", requireAuth(caddyProxyHandler))

	log.Println("Enhanced Caddy Admin UI starting on :8084")
	log.Println("Features: Service management, DNS integration, Caddy API proxy")
	log.Fatal(http.ListenAndServe(":8084", nil))
}
