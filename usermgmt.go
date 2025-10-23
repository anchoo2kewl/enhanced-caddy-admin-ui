package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"syscall"
	"text/tabwriter"
	"time"

	_ "modernc.org/sqlite"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

const dbPath = "./data/caddy-admin.db"

type CLIUser struct {
	ID        int
	Username  string
	IsAdmin   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

func main() {
	// Define subcommands
	addCmd := flag.NewFlagSet("add", flag.ExitOnError)
	addUsername := addCmd.String("username", "", "Username (required)")
	addPassword := addCmd.String("password", "", "Password (if not provided, will prompt)")
	addAdmin := addCmd.Bool("admin", false, "Make user an administrator")

	listCmd := flag.NewFlagSet("list", flag.ExitOnError)

	deleteCmd := flag.NewFlagSet("delete", flag.ExitOnError)
	deleteUsername := deleteCmd.String("username", "", "Username to delete (required)")

	resetCmd := flag.NewFlagSet("reset-password", flag.ExitOnError)
	resetUsername := resetCmd.String("username", "", "Username (required)")
	resetNewPassword := resetCmd.String("password", "", "New password (if not provided, will prompt)")

	// Check for subcommand
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// Open database
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Handle subcommands
	switch os.Args[1] {
	case "add":
		addCmd.Parse(os.Args[2:])
		if *addUsername == "" {
			fmt.Println("Error: username is required")
			addCmd.PrintDefaults()
			os.Exit(1)
		}

		password := *addPassword
		if password == "" {
			password = promptPassword("Enter password: ")
			confirmPassword := promptPassword("Confirm password: ")
			if password != confirmPassword {
				log.Fatal("Passwords do not match")
			}
		}

		if len(password) < 8 {
			log.Fatal("Password must be at least 8 characters")
		}

		if err := addUser(db, *addUsername, password, *addAdmin); err != nil {
			log.Fatalf("Failed to add user: %v", err)
		}
		fmt.Printf("✓ User '%s' created successfully\n", *addUsername)

	case "list":
		listCmd.Parse(os.Args[2:])
		if err := listUsers(db); err != nil {
			log.Fatalf("Failed to list users: %v", err)
		}

	case "delete":
		deleteCmd.Parse(os.Args[2:])
		if *deleteUsername == "" {
			fmt.Println("Error: username is required")
			deleteCmd.PrintDefaults()
			os.Exit(1)
		}

		if err := deleteUserByUsername(db, *deleteUsername); err != nil {
			log.Fatalf("Failed to delete user: %v", err)
		}
		fmt.Printf("✓ User '%s' deleted successfully\n", *deleteUsername)

	case "reset-password":
		resetCmd.Parse(os.Args[2:])
		if *resetUsername == "" {
			fmt.Println("Error: username is required")
			resetCmd.PrintDefaults()
			os.Exit(1)
		}

		password := *resetNewPassword
		if password == "" {
			password = promptPassword("Enter new password: ")
			confirmPassword := promptPassword("Confirm new password: ")
			if password != confirmPassword {
				log.Fatal("Passwords do not match")
			}
		}

		if len(password) < 8 {
			log.Fatal("Password must be at least 8 characters")
		}

		if err := resetUserPassword(db, *resetUsername, password); err != nil {
			log.Fatalf("Failed to reset password: %v", err)
		}
		fmt.Printf("✓ Password for '%s' reset successfully\n", *resetUsername)

	case "help", "-h", "--help":
		printUsage()

	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Caddy Admin User Management Tool")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  usermgmt <command> [options]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  add              Add a new user")
	fmt.Println("  list             List all users")
	fmt.Println("  delete           Delete a user")
	fmt.Println("  reset-password   Reset user password")
	fmt.Println("  help             Show this help message")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  # Add regular user (will prompt for password)")
	fmt.Println("  usermgmt add -username john")
	fmt.Println()
	fmt.Println("  # Add admin user with password")
	fmt.Println("  usermgmt add -username admin -password secret123 -admin")
	fmt.Println()
	fmt.Println("  # List all users")
	fmt.Println("  usermgmt list")
	fmt.Println()
	fmt.Println("  # Delete user")
	fmt.Println("  usermgmt delete -username john")
	fmt.Println()
	fmt.Println("  # Reset password (will prompt)")
	fmt.Println("  usermgmt reset-password -username john")
	fmt.Println()
}

func promptPassword(prompt string) string {
	fmt.Print(prompt)
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		log.Fatalf("Failed to read password: %v", err)
	}
	return string(bytePassword)
}

func addUser(db *sql.DB, username, password string, isAdmin bool) error {
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

func listUsers(db *sql.DB) error {
	rows, err := db.Query(`
		SELECT id, username, is_admin, created_at, updated_at
		FROM users ORDER BY created_at DESC`)
	if err != nil {
		return err
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "ID\tUSERNAME\tADMIN\tCREATED\tUPDATED")
	fmt.Fprintln(w, "---\t--------\t-----\t-------\t-------")

	for rows.Next() {
		var user CLIUser
		if err := rows.Scan(&user.ID, &user.Username, &user.IsAdmin, &user.CreatedAt, &user.UpdatedAt); err != nil {
			return err
		}

		adminStr := "No"
		if user.IsAdmin {
			adminStr = "Yes"
		}

		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n",
			user.ID,
			user.Username,
			adminStr,
			user.CreatedAt.Format("2006-01-02 15:04"),
			user.UpdatedAt.Format("2006-01-02 15:04"))
	}

	w.Flush()
	return nil
}

func deleteUserByUsername(db *sql.DB, username string) error {
	// Get user ID and check if admin
	var userID int
	var isAdmin bool
	err := db.QueryRow("SELECT id, is_admin FROM users WHERE username = ?", username).Scan(&userID, &isAdmin)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("user not found")
		}
		return err
	}

	// Check if this is the last admin
	if isAdmin {
		var adminCount int
		err := db.QueryRow("SELECT COUNT(*) FROM users WHERE is_admin = 1").Scan(&adminCount)
		if err != nil {
			return fmt.Errorf("failed to count admins: %v", err)
		}
		if adminCount <= 1 {
			return fmt.Errorf("cannot delete the last admin user")
		}
	}

	_, err = db.Exec("DELETE FROM users WHERE id = ?", userID)
	if err != nil {
		return fmt.Errorf("failed to delete user: %v", err)
	}
	return nil
}

func resetUserPassword(db *sql.DB, username, newPassword string) error {
	// Check if user exists
	var userID int
	err := db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("user not found")
		}
		return err
	}

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
