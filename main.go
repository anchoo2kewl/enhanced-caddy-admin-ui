package main

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/png"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/sessions"
	"github.com/pquerna/otp/totp"
	_ "modernc.org/sqlite"
	"golang.org/x/crypto/bcrypt"
)

var store = sessions.NewCookieStore([]byte("your-secret-key-here"))
var db *sql.DB

type User struct {
	ID          int       `json:"id"`
	Username    string    `json:"username"`
	Password    string    `json:"-"` // Never serialize password to JSON
	IsAdmin     bool      `json:"is_admin"`
	TwoFASecret string    `json:"-"` // Never serialize 2FA secret
	TwoFAEnabled bool      `json:"two_fa_enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type Service struct {
	ID            int    `json:"id"`
	Name          string `json:"name"`
	Subdomain     string `json:"subdomain"`
	Port          string `json:"port"`
	DestinationIP string `json:"destination_ip"`
	Description   string `json:"description"`
	Status        string `json:"status"`
	Icon          string `json:"icon"`
	Category      string `json:"category"`
	IsWebService  bool   `json:"is_web_service"`
}

type DNSRecord struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
}

var apiKeys = []string{
	// API keys will be generated and added here
	// Format: "your-api-key-here"
}

var services = []Service{
	// Dashboards
	{ID: 1, Name: "dashy.biswas.me", Subdomain: "dashy", Port: "4000", DestinationIP: "localhost", Description: "Main Dashboard", Status: "running", Icon: "🏠", Category: "Dashboard", IsWebService: true},
	{ID: 2, Name: "heimdall.biswas.me", Subdomain: "heimdall", Port: "3380", DestinationIP: "localhost", Description: "Application Dashboard", Status: "running", Icon: "🏡", Category: "Dashboard", IsWebService: true},

	// Management
	{ID: 3, Name: "dockge.biswas.me", Subdomain: "dockge", Port: "5002", DestinationIP: "localhost", Description: "Container Management", Status: "running", Icon: "🐳", Category: "Management", IsWebService: true},
	{ID: 4, Name: "vaultwarden.biswas.me", Subdomain: "vaultwarden", Port: "9480", DestinationIP: "localhost", Description: "Password Manager", Status: "running", Icon: "🔐", Category: "Security", IsWebService: true},
	{ID: 5, Name: "ha.biswas.me", Subdomain: "ha", Port: "8123", DestinationIP: "localhost", Description: "Home Assistant", Status: "running", Icon: "🏠", Category: "Automation", IsWebService: true},
	{ID: 6, Name: "n8n.biswas.me", Subdomain: "n8n", Port: "5678", DestinationIP: "localhost", Description: "Workflow Automation", Status: "running", Icon: "🔄", Category: "Automation", IsWebService: true},

	// Media & Entertainment
	{ID: 8, Name: "jellyfin.biswas.me", Subdomain: "jellyfin", Port: "8096", DestinationIP: "localhost", Description: "Media Server", Status: "running", Icon: "🎬", Category: "Media", IsWebService: true},
	{ID: 9, Name: "navidrome.biswas.me", Subdomain: "navidrome", Port: "4533", DestinationIP: "localhost", Description: "Music Server", Status: "running", Icon: "🎵", Category: "Media", IsWebService: true},
	{ID: 10, Name: "ab.biswas.me", Subdomain: "ab", Port: "13378", DestinationIP: "localhost", Description: "Audiobookshelf", Status: "running", Icon: "📚", Category: "Media", IsWebService: true},
	{ID: 11, Name: "photos.biswas.me", Subdomain: "photos", Port: "2283", DestinationIP: "localhost", Description: "Photo Management", Status: "running", Icon: "📸", Category: "Media", IsWebService: true},
	{ID: 12, Name: "romm.biswas.me", Subdomain: "romm", Port: "8181", DestinationIP: "localhost", Description: "ROM Management", Status: "running", Icon: "🎮", Category: "Media", IsWebService: true},

	// Productivity & Documents
	{ID: 13, Name: "calibre.biswas.me", Subdomain: "calibre", Port: "8083", DestinationIP: "localhost", Description: "E-book Management", Status: "running", Icon: "📖", Category: "Productivity", IsWebService: true},
	{ID: 14, Name: "paperless.biswas.me", Subdomain: "paperless", Port: "8000", DestinationIP: "localhost", Description: "Document Management", Status: "running", Icon: "📄", Category: "Productivity", IsWebService: true},
	{ID: 15, Name: "pdf.biswas.me", Subdomain: "pdf", Port: "8082", DestinationIP: "localhost", Description: "PDF Tools", Status: "running", Icon: "📋", Category: "Productivity", IsWebService: true},
	{ID: 16, Name: "wallabag.biswas.me", Subdomain: "wallabag", Port: "4480", DestinationIP: "localhost", Description: "Read Later", Status: "running", Icon: "📑", Category: "Productivity", IsWebService: true},

	// Finance & Planning
	{ID: 17, Name: "actual.biswas.me", Subdomain: "actual", Port: "5006", DestinationIP: "localhost", Description: "Budget Management", Status: "running", Icon: "💰", Category: "Finance", IsWebService: true},
	{ID: 18, Name: "firefly.biswas.me", Subdomain: "firefly", Port: "4480", DestinationIP: "localhost", Description: "Personal Finance", Status: "running", Icon: "💳", Category: "Finance", IsWebService: true},
	{ID: 19, Name: "karakeep.biswas.me", Subdomain: "karakeep", Port: "8081", DestinationIP: "localhost", Description: "Task Management", Status: "running", Icon: "✅", Category: "Planning", IsWebService: true},
	{ID: 20, Name: "mealie.biswas.me", Subdomain: "mealie", Port: "9925", DestinationIP: "localhost", Description: "Recipe Management", Status: "running", Icon: "🍳", Category: "Planning", IsWebService: true},

	// Development & API
	{ID: 21, Name: "api.biswas.me", Subdomain: "api", Port: "5000", DestinationIP: "localhost", Description: "API Gateway", Status: "running", Icon: "🔌", Category: "Development", IsWebService: true},
	{ID: 22, Name: "passwords.biswas.me", Subdomain: "passwords", Port: "13378", DestinationIP: "localhost", Description: "Password Service", Status: "running", Icon: "🔑", Category: "Security", IsWebService: true},
	{ID: 23, Name: "rustdesk.biswas.me", Subdomain: "rustdesk", Port: "21116", DestinationIP: "localhost", Description: "Remote Desktop Protocol", Status: "running", Icon: "🖥️", Category: "Remote", IsWebService: false},
}

const (
	CADDY_ADMIN_URL = "http://localhost:2019"
	CLOUDFLARE_ZONE = "biswas.me"
)

func init() {
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
	}
}

// Initialize database
func initDB() error {
	var err error
	db, err = sql.Open("sqlite", "./data/caddy-admin.db")
	if err != nil {
		return fmt.Errorf("failed to open database: %v", err)
	}

	// Create data directory if it doesn't exist
	if err := os.MkdirAll("./data", 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %v", err)
	}

	// Create users table
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		is_admin BOOLEAN NOT NULL DEFAULT 0,
		two_fa_secret TEXT DEFAULT '',
		two_fa_enabled BOOLEAN NOT NULL DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	`

	if _, err := db.Exec(createTableSQL); err != nil {
		return fmt.Errorf("failed to create users table: %v", err)
	}

	// Migrate existing tables to add 2FA columns if they don't exist
	db.Exec("ALTER TABLE users ADD COLUMN two_fa_secret TEXT DEFAULT ''")
	db.Exec("ALTER TABLE users ADD COLUMN two_fa_enabled BOOLEAN NOT NULL DEFAULT 0")

	// Create default admin user if no users exist
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to count users: %v", err)
	}

	if count == 0 {
		log.Println("No users found, creating default admin user...")
		hash, err := bcrypt.GenerateFromPassword([]byte("admin123!"), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash password: %v", err)
		}

		_, err = db.Exec("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
			"admin", string(hash), true)
		if err != nil {
			return fmt.Errorf("failed to create default admin user: %v", err)
		}
		log.Println("Created default admin user - username: admin, password: admin123!")
	}

	return nil
}

// User management functions
func getUserByUsername(username string) (*User, error) {
	var user User
	err := db.QueryRow(`
		SELECT id, username, password, is_admin, two_fa_secret, two_fa_enabled, created_at, updated_at
		FROM users WHERE username = ?`, username).Scan(
		&user.ID, &user.Username, &user.Password, &user.IsAdmin, &user.TwoFASecret, &user.TwoFAEnabled, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func getUserByID(id int) (*User, error) {
	var user User
	err := db.QueryRow(`
		SELECT id, username, password, is_admin, two_fa_secret, two_fa_enabled, created_at, updated_at
		FROM users WHERE id = ?`, id).Scan(
		&user.ID, &user.Username, &user.Password, &user.IsAdmin, &user.TwoFASecret, &user.TwoFAEnabled, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func getAllUsers() ([]User, error) {
	rows, err := db.Query(`
		SELECT id, username, password, is_admin, two_fa_secret, two_fa_enabled, created_at, updated_at
		FROM users ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Username, &user.Password, &user.IsAdmin, &user.TwoFASecret, &user.TwoFAEnabled, &user.CreatedAt, &user.UpdatedAt); err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}

func createUser(username, password string, isAdmin bool) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}

	_, err = db.Exec(`
		INSERT INTO users (username, password, is_admin, created_at, updated_at)
		VALUES (?, ?, ?, datetime('now'), datetime('now'))`,
		username, string(hash), isAdmin)
	if err != nil {
		return fmt.Errorf("failed to create user: %v", err)
	}
	return nil
}

func updateUserPassword(userID int, newPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}

	_, err = db.Exec(`
		UPDATE users SET password = ?, updated_at = datetime('now')
		WHERE id = ?`, string(hash), userID)
	if err != nil {
		return fmt.Errorf("failed to update password: %v", err)
	}
	return nil
}

func updateUserAdmin(userID int, isAdmin bool) error {
	_, err := db.Exec(`
		UPDATE users SET is_admin = ?, updated_at = datetime('now')
		WHERE id = ?`, isAdmin, userID)
	if err != nil {
		return fmt.Errorf("failed to update admin status: %v", err)
	}
	return nil
}

func deleteUser(userID int) error {
	// Prevent deleting the last admin
	var adminCount int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE is_admin = 1").Scan(&adminCount)
	if err != nil {
		return fmt.Errorf("failed to count admins: %v", err)
	}

	user, err := getUserByID(userID)
	if err != nil {
		return fmt.Errorf("user not found: %v", err)
	}

	if user.IsAdmin && adminCount <= 1 {
		return fmt.Errorf("cannot delete the last admin user")
	}

	_, err = db.Exec("DELETE FROM users WHERE id = ?", userID)
	if err != nil {
		return fmt.Errorf("failed to delete user: %v", err)
	}
	return nil
}

func authenticate(username, password string) bool {
	user, err := getUserByUsername(username)
	if err != nil {
		return false
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	return err == nil
}


// Helper function to get current user from session
func getCurrentUser(r *http.Request) (*User, error) {
	session, _ := store.Get(r, "session-name")
	username, ok := session.Values["username"].(string)
	if !ok {
		return nil, fmt.Errorf("not authenticated")
	}
	return getUserByUsername(username)
}

// Helper function to check if current user is admin
func isAdmin(r *http.Request) bool {
	user, err := getCurrentUser(r)
	if err != nil {
		return false
	}
	return user.IsAdmin
}

// Middleware to require admin access
func requireAdmin(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isAdmin(r) {
			http.Error(w, "Admin access required", http.StatusForbidden)
			return
		}
		handler(w, r)
	}
}

func requireAPIKey(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			apiKey = r.URL.Query().Get("api_key")
		}

		if apiKey == "" {
			http.Error(w, "API key required", http.StatusUnauthorized)
			return
		}

		validKey := false
		for _, key := range apiKeys {
			if key == apiKey {
				validKey = true
				break
			}
		}

		if !validKey {
			http.Error(w, "Invalid API key", http.StatusUnauthorized)
			return
		}

		handler(w, r)
	}
}

// Middleware to require either session auth or API key
func requireAuthOrAPIKey(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// First check if user has valid session
		session, _ := store.Get(r, "session-name")
		if auth, ok := session.Values["authenticated"].(bool); ok && auth {
			handler(w, r)
			return
		}

		// Otherwise check for API key
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			apiKey = r.URL.Query().Get("api_key")
		}

		if apiKey != "" {
			validKey := false
			for _, key := range apiKeys {
				if key == apiKey {
					validKey = true
					break
				}
			}

			if validKey {
				handler(w, r)
				return
			}
		}

		http.Error(w, "Authentication required (session or API key)", http.StatusUnauthorized)
	}
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

func updateCaddyConfig(service Service) error {
	// Use DestinationIP if provided, otherwise default to localhost
	destinationIP := service.DestinationIP
	if destinationIP == "" {
		destinationIP = "localhost"
	}

	config := map[string]interface{}{
		"@id": service.Subdomain,
		"match": []map[string]interface{}{
			{"host": []string{service.Name}},
		},
		"handle": []map[string]interface{}{
			{
				"handler": "reverse_proxy",
				"upstreams": []map[string]interface{}{
					{"dial": fmt.Sprintf("%s:%s", destinationIP, service.Port)},
				},
			},
		},
	}

	jsonData, err := json.Marshal(config)
	if err != nil {
		return err
	}

	resp, err := http.Post(fmt.Sprintf("%s/config/apps/http/servers/srv0/routes", CADDY_ADMIN_URL),
		"application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func createDNSRecord(subdomain string) error {
	// Read Cloudflare credentials from environment
	apiToken := os.Getenv("CLOUDFLARE_API_TOKEN")
	if apiToken == "" {
		// Try reading from Caddy's env file
		data, err := os.ReadFile("/etc/caddy/cloudflare.env")
		if err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "CLOUDFLARE_API_TOKEN=") {
					apiToken = strings.TrimPrefix(line, "CLOUDFLARE_API_TOKEN=")
					apiToken = strings.TrimSpace(apiToken)
					break
				}
			}
		}
	}

	zoneID := os.Getenv("CLOUDFLARE_ZONE_ID")
	if zoneID == "" {
		// Try reading from Caddy's env file
		data, err := os.ReadFile("/etc/caddy/cloudflare.env")
		if err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "CLOUDFLARE_ZONE_ID=") {
					zoneID = strings.TrimPrefix(line, "CLOUDFLARE_ZONE_ID=")
					zoneID = strings.TrimSpace(zoneID)
					break
				}
			}
		}
	}

	cnameTarget := os.Getenv("CNAME_TARGET")
	if cnameTarget == "" {
		cnameTarget = "anshuman.duckdns.com" // Default fallback
	}

	if apiToken == "" || zoneID == "" {
		log.Printf("Warning: Cloudflare API credentials not set, skipping DNS creation for %s", subdomain)
		return nil
	}

	recordName := fmt.Sprintf("%s.%s", subdomain, CLOUDFLARE_ZONE)

	// Create DNS record payload
	dnsRecord := DNSRecord{
		Type:    "CNAME",
		Name:    recordName,
		Content: cnameTarget,
		TTL:     1, // Auto TTL
	}

	jsonData, err := json.Marshal(dnsRecord)
	if err != nil {
		return fmt.Errorf("failed to marshal DNS record: %v", err)
	}

	createURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", zoneID)

	req, err := http.NewRequest("POST", createURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiToken))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to create DNS record: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %v", err)
	}

	var createResult struct {
		Success bool   `json:"success"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}

	if err := json.Unmarshal(body, &createResult); err != nil {
		return fmt.Errorf("failed to parse response: %v", err)
	}

	if !createResult.Success {
		if len(createResult.Errors) > 0 {
			errorMsg := createResult.Errors[0].Message
			// If record already exists, that's fine - just log and continue
			if strings.Contains(errorMsg, "already exists") {
				log.Printf("DNS record already exists: %s CNAME %s (skipping)", recordName, cnameTarget)
				return nil
			}
			return fmt.Errorf("cloudflare API error: %s", errorMsg)
		}
		return fmt.Errorf("cloudflare API returned success=false")
	}

	log.Printf("Successfully created DNS record: %s CNAME %s", recordName, cnameTarget)
	return nil
}

func listDNSRecords() ([]map[string]interface{}, error) {
	// Read Cloudflare credentials from environment
	apiToken := os.Getenv("CLOUDFLARE_API_TOKEN")
	if apiToken == "" {
		// Try reading from Caddy's env file
		data, err := os.ReadFile("/etc/caddy/cloudflare.env")
		if err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "CLOUDFLARE_API_TOKEN=") {
					apiToken = strings.TrimPrefix(line, "CLOUDFLARE_API_TOKEN=")
					apiToken = strings.TrimSpace(apiToken)
					break
				}
			}
		}
	}

	zoneID := os.Getenv("CLOUDFLARE_ZONE_ID")
	if zoneID == "" {
		// Try reading from Caddy's env file
		data, err := os.ReadFile("/etc/caddy/cloudflare.env")
		if err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "CLOUDFLARE_ZONE_ID=") {
					zoneID = strings.TrimPrefix(line, "CLOUDFLARE_ZONE_ID=")
					zoneID = strings.TrimSpace(zoneID)
					break
				}
			}
		}
	}

	if apiToken == "" || zoneID == "" {
		return nil, fmt.Errorf("cloudflare API credentials not set")
	}

	listURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", zoneID)

	req, err := http.NewRequest("GET", listURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiToken))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list DNS records: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	var listResult struct {
		Success bool                     `json:"success"`
		Result  []map[string]interface{} `json:"result"`
	}

	if err := json.Unmarshal(body, &listResult); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	if !listResult.Success {
		return nil, fmt.Errorf("cloudflare API returned success=false")
	}

	return listResult.Result, nil
}

func deleteDNSRecord(subdomain string) error {
	// Read Cloudflare credentials from environment
	apiToken := os.Getenv("CLOUDFLARE_API_TOKEN")
	if apiToken == "" {
		// Try reading from Caddy's env file
		data, err := os.ReadFile("/etc/caddy/cloudflare.env")
		if err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "CLOUDFLARE_API_TOKEN=") {
					apiToken = strings.TrimPrefix(line, "CLOUDFLARE_API_TOKEN=")
					apiToken = strings.TrimSpace(apiToken)
					break
				}
			}
		}
	}

	zoneID := os.Getenv("CLOUDFLARE_ZONE_ID")
	if zoneID == "" {
		// Try reading from Caddy's env file
		data, err := os.ReadFile("/etc/caddy/cloudflare.env")
		if err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "CLOUDFLARE_ZONE_ID=") {
					zoneID = strings.TrimPrefix(line, "CLOUDFLARE_ZONE_ID=")
					zoneID = strings.TrimSpace(zoneID)
					break
				}
			}
		}
	}

	if apiToken == "" || zoneID == "" {
		log.Printf("Warning: Cloudflare API credentials not set, skipping DNS deletion for %s", subdomain)
		return nil
	}

	recordName := fmt.Sprintf("%s.%s", subdomain, CLOUDFLARE_ZONE)
	
	// First, get the DNS record ID
	listURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records?name=%s", zoneID, recordName)
	
	req, err := http.NewRequest("GET", listURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiToken))
	req.Header.Set("Content-Type", "application/json")
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to list DNS records: %v", err)
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %v", err)
	}
	
	var listResult struct {
		Success bool `json:"success"`
		Result  []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"result"`
	}
	
	if err := json.Unmarshal(body, &listResult); err != nil {
		return fmt.Errorf("failed to parse response: %v", err)
	}
	
	if !listResult.Success || len(listResult.Result) == 0 {
		log.Printf("No DNS record found for %s, skipping deletion", recordName)
		return nil
	}
	
	// Delete the DNS record
	recordID := listResult.Result[0].ID
	deleteURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zoneID, recordID)
	
	req, err = http.NewRequest("DELETE", deleteURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create delete request: %v", err)
	}
	
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiToken))
	req.Header.Set("Content-Type", "application/json")
	
	resp, err = client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to delete DNS record: %v", err)
	}
	defer resp.Body.Close()
	
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read delete response: %v", err)
	}
	
	var deleteResult struct {
		Success bool `json:"success"`
	}
	
	if err := json.Unmarshal(body, &deleteResult); err != nil {
		return fmt.Errorf("failed to parse delete response: %v", err)
	}
	
	if !deleteResult.Success {
		return fmt.Errorf("cloudflare API returned success=false")
	}
	
	log.Printf("Successfully deleted DNS record: %s", recordName)
	return nil
}

func testServiceHealth(serviceName string) (int, error) {
	client := &http.Client{}
	req, err := http.NewRequest("HEAD", fmt.Sprintf("https://%s", serviceName), nil)
	if err != nil {
		return 0, err
	}
	
	req.Header.Set("User-Agent", "CaddyAdminUI/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	
	return resp.StatusCode, nil
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		loginHTML := `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Caddy Admin Login</title>
	<link rel="icon" type="image/svg+xml" href="/favicon.svg">
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
		button:disabled { background: #cbd5e0; cursor: not-allowed; }
		.error { color: #e53e3e; margin-bottom: 20px; padding: 10px; background: #fed7d7; border-radius: 6px; }
		.info { color: #3182ce; margin-bottom: 20px; padding: 10px; background: #bee3f8; border-radius: 6px; }
		.hidden { display: none; }
	</style>
</head>
<body>
	<div class="login-container">
		<h1>🚀 Caddy Admin</h1>
		<div id="errorMsg" class="error hidden"></div>
		<div id="infoMsg" class="info hidden"></div>

		<!-- Initial login form -->
		<form id="loginForm">
			<div class="form-group">
				<label for="username">Username</label>
				<input type="text" id="username" name="username" required>
			</div>
			<div class="form-group">
				<label for="password">Password</label>
				<input type="password" id="password" name="password" required>
			</div>
			<button type="submit" id="loginBtn">Login</button>
		</form>

		<!-- 2FA verification form (hidden initially) -->
		<form id="twoFAForm" class="hidden">
			<div class="form-group">
				<label for="twofa_code">Two-Factor Authentication Code</label>
				<input type="text" id="twofa_code" name="code" placeholder="Enter 6-digit code" maxlength="6" pattern="[0-9]{6}" required>
				<small style="color: #718096; margin-top: 4px; display: block;">Enter the 6-digit code from your authenticator app</small>
			</div>
			<button type="submit" id="verifyBtn">Verify</button>
			<button type="button" id="backBtn" style="background: #718096; margin-top: 10px;">Back to Login</button>
		</form>
	</div>

	<script>
		const loginForm = document.getElementById('loginForm');
		const twoFAForm = document.getElementById('twoFAForm');
		const errorMsg = document.getElementById('errorMsg');
		const infoMsg = document.getElementById('infoMsg');

		function showError(msg) {
			errorMsg.textContent = msg;
			errorMsg.classList.remove('hidden');
			infoMsg.classList.add('hidden');
		}

		function showInfo(msg) {
			infoMsg.textContent = msg;
			infoMsg.classList.remove('hidden');
			errorMsg.classList.add('hidden');
		}

		function hideMessages() {
			errorMsg.classList.add('hidden');
			infoMsg.classList.add('hidden');
		}

		// Handle initial login
		loginForm.addEventListener('submit', async (e) => {
			e.preventDefault();
			hideMessages();

			const formData = new FormData(loginForm);
			const loginBtn = document.getElementById('loginBtn');
			loginBtn.disabled = true;
			loginBtn.textContent = 'Logging in...';

			try {
				const response = await fetch('/login', {
					method: 'POST',
					body: formData
				});

				if (response.redirected) {
					// Normal login succeeded (no 2FA)
					window.location.href = response.url;
					return;
				}

				if (response.ok) {
					const data = await response.json();
					if (data.requires_2fa) {
						// Show 2FA form
						showInfo('Please enter your two-factor authentication code');
						loginForm.classList.add('hidden');
						twoFAForm.classList.remove('hidden');
						document.getElementById('twofa_code').focus();
					}
				} else {
					showError('Invalid username or password');
				}
			} catch (err) {
				showError('Login failed. Please try again.');
			} finally {
				loginBtn.disabled = false;
				loginBtn.textContent = 'Login';
			}
		});

		// Handle 2FA verification
		twoFAForm.addEventListener('submit', async (e) => {
			e.preventDefault();
			hideMessages();

			const code = document.getElementById('twofa_code').value;
			const verifyBtn = document.getElementById('verifyBtn');
			verifyBtn.disabled = true;
			verifyBtn.textContent = 'Verifying...';

			try {
				const response = await fetch('/api/2fa/verify', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ code })
				});

				if (response.ok) {
					window.location.href = '/';
				} else {
					const error = await response.text();
					showError('Invalid code. Please try again.');
					document.getElementById('twofa_code').value = '';
					document.getElementById('twofa_code').focus();
				}
			} catch (err) {
				showError('Verification failed. Please try again.');
			} finally {
				verifyBtn.disabled = false;
				verifyBtn.textContent = 'Verify';
			}
		});

		// Back button
		document.getElementById('backBtn').addEventListener('click', () => {
			hideMessages();
			twoFAForm.classList.add('hidden');
			loginForm.classList.remove('hidden');
			document.getElementById('username').focus();
			document.getElementById('twofa_code').value = '';
		});
	</script>
</body>
</html>`
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(loginHTML))
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if authenticate(username, password) {
		user, err := getUserByUsername(username)
		if err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		// Check if 2FA is enabled for this user
		if user.TwoFAEnabled {
			session, _ := store.Get(r, "session-name")
			session.Values["pending_2fa_username"] = username
			session.Save(r, w)

			// Return JSON indicating 2FA required
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]bool{"requires_2fa": true})
			return
		}

		// Normal login (no 2FA)
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

		newService.ID = len(services) + 1
		newService.Name = fmt.Sprintf("%s.biswas.me", newService.Subdomain)
		newService.Status = "running"
		newService.Icon = "🔧"
		if newService.Category == "" {
			newService.Category = "Custom"
		}
		// Default values for new fields
		if newService.DestinationIP == "" {
			newService.DestinationIP = "localhost"
		}
		// Default to web service if not specified
		if !newService.IsWebService {
			newService.IsWebService = true
		}

		if err := createDNSRecord(newService.Subdomain); err != nil {
			log.Printf("Error creating DNS record: %v", err)
		}

		// Only configure Caddy for web services
		if newService.IsWebService {
			if err := updateCaddyConfig(newService); err != nil {
				log.Printf("Error updating Caddy config: %v", err)
			}
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

		for i, service := range services {
			if service.ID == id {
				oldSubdomain := service.Subdomain

				services[i].Description = updatedService.Description
				services[i].Port = updatedService.Port

				if updatedService.Subdomain != oldSubdomain {
					if err := deleteDNSRecord(oldSubdomain); err != nil {
						log.Printf("Error deleting old DNS record: %v", err)
					}

					if err := createDNSRecord(updatedService.Subdomain); err != nil {
						log.Printf("Error creating new DNS record: %v", err)
					}

					services[i].Subdomain = updatedService.Subdomain
					services[i].Name = fmt.Sprintf("%s.biswas.me", updatedService.Subdomain)
				}

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
				if err := deleteDNSRecord(service.Subdomain); err != nil {
					log.Printf("Error deleting DNS record: %v", err)
				}

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

func apiTestServiceHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		ServiceName string `json:"service_name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	statusCode, err := testServiceHealth(request.ServiceName)
	
	response := map[string]interface{}{
		"service_name": request.ServiceName,
		"status_code": statusCode,
		"success": err == nil && statusCode >= 200 && statusCode < 400,
	}

	if err != nil {
		response["error"] = err.Error()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func caddyProxyHandler(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/caddy-api")
	targetURL := CADDY_ADMIN_URL + path

	req, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		http.Error(w, "Error creating request", http.StatusInternalServerError)
		return
	}

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

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}


func apiDNSHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		// List all DNS records
		records, err := listDNSRecords()
		if err != nil {
			log.Printf("Error listing DNS records: %v", err)
			http.Error(w, fmt.Sprintf("Failed to list DNS records: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "success",
			"records": records,
			"count":   len(records),
		})

	case "DELETE":
		var req struct {
			Subdomain string `json:"subdomain"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if req.Subdomain == "" {
			http.Error(w, "Subdomain is required", http.StatusBadRequest)
			return
		}

		if err := deleteDNSRecord(req.Subdomain); err != nil {
			log.Printf("Error deleting DNS record: %v", err)
			http.Error(w, fmt.Sprintf("Failed to delete DNS record: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "success",
			"message": fmt.Sprintf("DNS record for %s.%s deleted", req.Subdomain, CLOUDFLARE_ZONE),
		})

	case "POST":
		var req struct {
			Subdomain string `json:"subdomain"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if req.Subdomain == "" {
			http.Error(w, "Subdomain is required", http.StatusBadRequest)
			return
		}

		// Create DNS record
		if err := createDNSRecord(req.Subdomain); err != nil {
			log.Printf("Error creating DNS record: %v", err)
			http.Error(w, fmt.Sprintf("Failed to create DNS record: %v", err), http.StatusInternalServerError)
			return
		}

		// Find service by subdomain and configure Caddy
		var foundService *Service
		for i := range services {
			if services[i].Subdomain == req.Subdomain {
				foundService = &services[i]
				break
			}
		}

		if foundService != nil && foundService.IsWebService {
			if err := updateCaddyConfig(*foundService); err != nil {
				log.Printf("Warning: DNS created but Caddy config failed: %v", err)
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]string{
					"status": "partial",
					"message": fmt.Sprintf("DNS record created, but Caddy config failed: %v", err),
				})
				return
			}
			log.Printf("Configured Caddy for service: %s", foundService.Name)
		}

		w.Header().Set("Content-Type", "application/json")
		responseMsg := fmt.Sprintf("DNS record for %s.%s created", req.Subdomain, CLOUDFLARE_ZONE)
		if foundService != nil {
			if foundService.IsWebService {
				responseMsg += fmt.Sprintf(" and Caddy configured for %s", foundService.Name)
			} else {
				responseMsg += fmt.Sprintf(" (protocol service - Caddy not configured)")
			}
		}
		json.NewEncoder(w).Encode(map[string]string{
			"status": "success",
			"message": responseMsg,
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}


func apiKeysHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		// List API keys (masked)
		masked := make([]map[string]string, len(apiKeys))
		for i, key := range apiKeys {
			if len(key) > 8 {
				masked[i] = map[string]string{
					"id": fmt.Sprintf("%d", i),
					"key": key[:4] + "..." + key[len(key)-4:],
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(masked)
		
	case "POST":
		// Generate new API key
		apiKey := fmt.Sprintf("cak_%s", generateRandomString(32))
		apiKeys = append(apiKeys, apiKey)
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "success",
			"api_key": apiKey,
			"message": "API key generated. Save it securely - it won't be shown again.",
		})
		
	case "DELETE":
		var req struct {
			ID int `json:"id"`
		}
		
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		
		if req.ID < 0 || req.ID >= len(apiKeys) {
			http.Error(w, "Invalid API key ID", http.StatusBadRequest)
			return
		}
		
		apiKeys = append(apiKeys[:req.ID], apiKeys[req.ID+1:]...)
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "success",
			"message": "API key deleted",
		})
		
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// User management handlers
func usersHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		users, err := getAllUsers()
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to get users: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(users)

	case "POST":
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			IsAdmin  bool   `json:"is_admin"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if req.Username == "" || req.Password == "" {
			http.Error(w, "Username and password are required", http.StatusBadRequest)
			return
		}

		if len(req.Password) < 8 {
			http.Error(w, "Password must be at least 8 characters", http.StatusBadRequest)
			return
		}

		if err := createUser(req.Username, req.Password, req.IsAdmin); err != nil {
			http.Error(w, fmt.Sprintf("Failed to create user: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "success",
			"message": "User created successfully",
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func userHandler(w http.ResponseWriter, r *http.Request) {
	// Extract user ID from URL
	idStr := strings.TrimPrefix(r.URL.Path, "/api/users/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case "GET":
		user, err := getUserByID(id)
		if err != nil {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(user)

	case "PUT":
		var req struct {
			IsAdmin *bool `json:"is_admin,omitempty"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if req.IsAdmin != nil {
			if err := updateUserAdmin(id, *req.IsAdmin); err != nil {
				http.Error(w, fmt.Sprintf("Failed to update user: %v", err), http.StatusInternalServerError)
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "success",
			"message": "User updated successfully",
		})

	case "DELETE":
		if err := deleteUser(id); err != nil {
			http.Error(w, fmt.Sprintf("Failed to delete user: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "success",
			"message": "User deleted successfully",
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func changePasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.CurrentPassword == "" || req.NewPassword == "" {
		http.Error(w, "Current password and new password are required", http.StatusBadRequest)
		return
	}

	if len(req.NewPassword) < 8 {
		http.Error(w, "New password must be at least 8 characters", http.StatusBadRequest)
		return
	}

	// Get current user
	user, err := getCurrentUser(r)
	if err != nil {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	// Verify current password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.CurrentPassword)); err != nil {
		http.Error(w, "Current password is incorrect", http.StatusUnauthorized)
		return
	}

	// Update password
	if err := updateUserPassword(user.ID, req.NewPassword); err != nil {
		http.Error(w, fmt.Sprintf("Failed to update password: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Password changed successfully",
	})
}

func currentUserHandler(w http.ResponseWriter, r *http.Request) {
	user, err := getCurrentUser(r)
	if err != nil {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

// 2FA Handlers
func setup2FAHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user, err := getCurrentUser(r)
	if err != nil {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	// Generate TOTP secret
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Caddy Admin",
		AccountName: user.Username,
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to generate 2FA secret: %v", err), http.StatusInternalServerError)
		return
	}

	// Save secret to database (but don't enable yet)
	_, err = db.Exec("UPDATE users SET two_fa_secret = ?, updated_at = datetime('now') WHERE id = ?",
		key.Secret(), user.ID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to save 2FA secret: %v", err), http.StatusInternalServerError)
		return
	}

	// Generate QR code
	img, err := key.Image(200, 200)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to generate QR code: %v", err), http.StatusInternalServerError)
		return
	}

	// Convert image to base64
	var buf bytes.Buffer
	png.Encode(&buf, img)
	qrCode := base64.StdEncoding.EncodeToString(buf.Bytes())

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"secret":      key.Secret(),
		"qr_code":     qrCode,
		"manual_code": key.Secret(),
		"issuer":      "Caddy Admin",
		"account":     user.Username,
	})
}

func enable2FAHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user, err := getCurrentUser(r)
	if err != nil {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Get fresh user data with secret
	user, err = getUserByID(user.ID)
	if err != nil || user.TwoFASecret == "" {
		http.Error(w, "2FA not set up. Call /api/2fa/setup first", http.StatusBadRequest)
		return
	}

	// Verify the code
	valid := totp.Validate(req.Code, user.TwoFASecret)
	if !valid {
		http.Error(w, "Invalid code", http.StatusUnauthorized)
		return
	}

	// Enable 2FA
	_, err = db.Exec("UPDATE users SET two_fa_enabled = 1, updated_at = datetime('now') WHERE id = ?", user.ID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to enable 2FA: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "2FA enabled successfully",
	})
}

func disable2FAHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user, err := getCurrentUser(r)
	if err != nil {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Verify password
	user, _ = getUserByID(user.ID)
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	// Disable 2FA
	_, err = db.Exec("UPDATE users SET two_fa_enabled = 0, two_fa_secret = '', updated_at = datetime('now') WHERE id = ?", user.ID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to disable 2FA: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "2FA disabled successfully",
	})
}

func verify2FAHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session, _ := store.Get(r, "session-name")
	username, ok := session.Values["pending_2fa_username"].(string)
	if !ok {
		http.Error(w, "No pending 2FA verification", http.StatusBadRequest)
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	user, err := getUserByUsername(username)
	if err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	// Verify the code
	valid := totp.Validate(req.Code, user.TwoFASecret)
	if !valid {
		http.Error(w, "Invalid code", http.StatusUnauthorized)
		return
	}

	// Complete login
	delete(session.Values, "pending_2fa_username")
	session.Values["authenticated"] = true
	session.Values["username"] = username
	session.Save(r, w)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Login successful",
	})
}

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	randomBytes := make([]byte, length)

	// Use crypto/rand for secure random generation
	_, err := rand.Read(randomBytes)
	if err != nil {
		log.Printf("Warning: Failed to generate secure random string: %v", err)
		// This should rarely happen, but just in case
		return fmt.Sprintf("err_%d", len(result))
	}

	for i, b := range randomBytes {
		result[i] = charset[int(b)%len(charset)]
	}
	return string(result)
}

func main() {
	// Initialize database
	if err := initDB(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	if os.Getenv("CADDY_ADMIN_URL") != "" {
		log.Printf("Using Caddy Admin API at: %s", os.Getenv("CADDY_ADMIN_URL"))
	}

	// Configure all web services in Caddy on startup
	log.Println("Configuring web services in Caddy...")
	for _, service := range services {
		if service.IsWebService {
			if err := updateCaddyConfig(service); err != nil {
				log.Printf("Warning: Failed to configure %s in Caddy: %v", service.Name, err)
			} else {
				log.Printf("Configured: %s", service.Name)
			}
		}
	}

	// Authentication routes
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)

	// Static files (no auth required)
	http.HandleFunc("/favicon.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		http.ServeFile(w, r, "html/favicon.svg")
	})
	http.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/favicon.svg", http.StatusMovedPermanently)
	})

	// Dashboard
	http.HandleFunc("/", requireAuth(dashboardHandler))

	// Service management
	http.HandleFunc("/api/services", requireAuth(apiServicesHandler))
	http.HandleFunc("/api/services/", requireAuth(apiServiceHandler))
	http.HandleFunc("/api/test-service", requireAuth(apiTestServiceHandler))

	// DNS management (requires authentication or API key)
	http.HandleFunc("/api/dns", requireAuthOrAPIKey(apiDNSHandler))

	// API keys management
	http.HandleFunc("/api/keys", requireAuth(apiKeysHandler))

	// User management (admin only)
	http.HandleFunc("/api/users", requireAuth(requireAdmin(usersHandler)))
	http.HandleFunc("/api/users/", requireAuth(requireAdmin(userHandler)))

	// Password change (any authenticated user)
	http.HandleFunc("/api/change-password", requireAuth(changePasswordHandler))

	// 2FA management (any authenticated user)
	http.HandleFunc("/api/2fa/setup", requireAuth(setup2FAHandler))
	http.HandleFunc("/api/2fa/enable", requireAuth(enable2FAHandler))
	http.HandleFunc("/api/2fa/disable", requireAuth(disable2FAHandler))
	http.HandleFunc("/api/2fa/verify", verify2FAHandler) // No auth required - this IS the auth step

	// Current user info
	http.HandleFunc("/api/me", requireAuth(currentUserHandler))

	// Caddy proxy
	http.HandleFunc("/caddy-api/", requireAuth(caddyProxyHandler))

	log.Println("Enhanced Caddy Admin UI starting on :8084")
	log.Println("Features: Service management, DNS integration, Caddy API proxy, Service testing, User management")
	log.Fatal(http.ListenAndServe(":8084", nil))
}
