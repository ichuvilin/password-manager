package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"
)

const (
	lowerLatter = "abcdefghijklmnopqrstuvwxyz"
	upperLatter = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digit       = "0123456789"
	special     = "!@#$%^&*()-_=+[]{}|;:',.<>?/~`"

	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorReset  = "\033[0m"
)

// Password represents a stored password entry.
type Password struct {
	Name         string    `json:"name"`
	Value        string    `json:"value"`
	Category     string    `json:"category"`
	CreatedAt    time.Time `json:"created_at"`
	LastModified time.Time `json:"last_modified"`
}

// PasswordManager manages stored passwords and handles their encryption and persistence.
type PasswordManager struct {
	passwords     map[string]Password `json:"passwords"`
	masterKey     []byte              `json:"-"`
	filePath      string              `json:"-"`
	isInitialized bool                `json:"-"`
}

// NewPasswordManager creates a new password manager with an empty password store.
func NewPasswordManager(filePath string) *PasswordManager {
	return &PasswordManager{
		passwords:     make(map[string]Password),
		filePath:      filePath,
		isInitialized: false,
	}
}

// NewPassword creates a new password entry.
func NewPassword(name, value, category string) Password {
	return Password{Name: name, Value: value, Category: category, CreatedAt: time.Now(), LastModified: time.Now()}
}

// SetMasterPassword sets and initializes the master password.
func (pm *PasswordManager) SetMasterPassword(masterPassword string) error {
	if masterPassword == "" || len(masterPassword) < 8 {
		return errors.New("password is too weak")
	}
	buf := make([]byte, 32)
	copy(buf, []byte(masterPassword))

	pm.masterKey = buf
	pm.isInitialized = true
	return nil
}

// SavePassword adds a new password to the password store.
func (pm *PasswordManager) SavePassword(name, value, category string) error {
	if !pm.isInitialized {
		return errors.New("password manager not initialized")
	}

	if err := pm.CheckPasswordStrength(value); err != nil {
		return err
	}

	_, ok := pm.passwords[name]
	if ok {
		return errors.New("password already exists")
	}

	pm.passwords[name] = NewPassword(name, value, category)

	return nil
}

// GetPassword returns a password by its service name.
func (pm *PasswordManager) GetPassword(name string) (Password, error) {
	if !pm.isInitialized {
		return Password{}, errors.New("password manager not initialized")
	}

	passwd, ok := pm.passwords[name]
	if !ok {
		return Password{}, errors.New("password not found")
	}
	return passwd, nil
}

// ListPasswords returns all stored passwords.
func (pm *PasswordManager) ListPasswords() []Password {
	passwords := make([]Password, 0, len(pm.passwords))

	for _, v := range pm.passwords {
		passwords = append(passwords, v)
	}

	return passwords
}

// GeneratePassword generates a random password of the specified length.
func (pm *PasswordManager) GeneratePassword(length int) (string, error) {
	if length < 8 {
		return "", errors.New("password is too weak")
	}

	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}

	charset := lowerLatter + upperLatter + digit + special

	password := make([]byte, length)

	for i, b := range buf {
		password[i] = charset[int(b)%len(charset)]
	}

	return string(password), nil
}

// SaveToFile encrypts the password store and saves it to the configured file.
func (pm *PasswordManager) SaveToFile() error {
	if !pm.isInitialized {
		return errors.New("password manager not initialized")
	}

	data, err := json.Marshal(pm.passwords)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(pm.masterKey)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	encryptedData := gcm.Seal(nil, nonce, data, nil)

	file, err := os.Create(pm.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.Write(nonce); err != nil {
		return err
	}

	if _, err := file.Write(encryptedData); err != nil {
		return err
	}

	return nil
}

// LoadFromFile loads and decrypts the password store from the configured file.
func (pm *PasswordManager) LoadFromFile() error {
	if !pm.isInitialized {
		return errors.New("password manager not initialized")
	}
	file, err := os.Open(pm.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	block, err := aes.NewCipher(pm.masterKey)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())

	if _, err := io.ReadFull(file, nonce); err != nil {
		return err
	}

	encryptedData, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	decryptedData, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(decryptedData, &pm.passwords); err != nil {
		return err
	}

	return nil
}

// CheckPasswordStrength validates that a password meets the required strength criteria.
func (pm *PasswordManager) CheckPasswordStrength(password string) error {
	var (
		hasUpper   bool
		hasLower   bool
		hasDigit   bool
		hasSpecial bool
	)

	if len(password) < 8 {
		return errors.New("password is too weak")
	}

	for _, r := range password {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		case strings.ContainsRune(special, r):
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
		return errors.New("password must contain uppercase, lowercase, digit and special character")
	}

	return nil
}

// GetPasswordsByCategory returns all passwords belonging to the specified category.
func (pm *PasswordManager) GetPasswordsByCategory(category string) []Password {
	result := make([]Password, 0)

	for _, p := range pm.passwords {
		if strings.ToLower(p.Category) == strings.ToLower(category) {
			result = append(result, p)
		}
	}

	return result
}

// FindDuplicatePasswords returns passwords that are used by multiple services.
func (pm *PasswordManager) FindDuplicatePasswords() map[string][]string {
	result := make(map[string][]string)

	for _, p := range pm.passwords {
		result[p.Value] = append(result[p.Value], p.Name)
	}

	for k, v := range result {
		if len(v) == 1 {
			delete(result, k)
		}
	}

	return result
}

// UpdatePassword updates the password value for the specified service.
func (pm *PasswordManager) UpdatePassword(name, newValue string) error {
	value, ok := pm.passwords[name]
	if !ok {
		return errors.New("password not found")
	}
	if err := pm.CheckPasswordStrength(newValue); err != nil {
		return err
	}
	value.Value = newValue
	value.LastModified = time.Now()
	pm.passwords[name] = value
	return nil
}

// DeletePassword removes the password associated with the specified service.
func (pm *PasswordManager) DeletePassword(name string) error {
	if !pm.isInitialized {
		return errors.New("password manager not initialized")
	}

	_, ok := pm.passwords[name]
	if !ok {
		return errors.New("password not found")
	}

	delete(pm.passwords, name)

	return nil
}

// ListCategories returns all categories used by stored passwords.
func (pm *PasswordManager) ListCategories() []string {
	set := make(map[string]bool)

	for _, v := range pm.passwords {
		set[v.Category] = true
	}

	result := make([]string, 0, len(set))
	for k, _ := range set {
		result = append(result, k)
	}

	return result
}

// GetPasswordStats returns statistics about the stored passwords.
func (pm *PasswordManager) GetPasswordStats() map[string]interface{} {
	result := make(map[string]interface{})

	result["total"] = len(pm.passwords)

	categories := pm.ListCategories()
	for _, cat := range categories {
		result[cat] = len(pm.GetPasswordsByCategory(cat))
	}

	var minCreatedAt time.Time
	var maxCreatedAt time.Time
	var initialized bool

	for _, p := range pm.passwords {
		if !initialized {
			minCreatedAt = p.CreatedAt
			maxCreatedAt = p.CreatedAt
			initialized = true
			continue
		}

		if p.CreatedAt.Before(minCreatedAt) {
			minCreatedAt = p.CreatedAt
		}
		if p.CreatedAt.After(maxCreatedAt) {
			maxCreatedAt = p.CreatedAt
		}
	}

	result["oldest"] = minCreatedAt
	result["newest"] = maxCreatedAt

	return result
}

// clearScreen clears the terminal screen.
func clearScreen() {
	fmt.Print("\033[H\033[2J")
}

// showSuccess displays a success message in the terminal.
func showSuccess(message string) {
	fmt.Printf("%s✓ Success: %s%s\n", colorGreen, message, colorReset)
}

// showError displays an error message in the terminal.
func showError(message string) {
	fmt.Printf("%s✗ Error: %s%s\n", colorRed, message, colorReset)
}

// showInfo displays an informational message in the terminal.
func showInfo(message string) {
	fmt.Printf("%s→ Info: %s%s\n", colorYellow, message, colorReset)
}

// waitForEnter waits for the user to press Enter.
func waitForEnter() {
	fmt.Print("\nPress Enter to continue...")

	reader := bufio.NewReader(os.Stdin)
	_, _ = reader.ReadString('\n')
}

// ReadUserInput reads a line of input from the user and removes leading and trailing whitespace.
func ReadUserInput(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

// readPassword securely reads a password from the terminal without displaying it.
func readPassword() (string, error) {
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	fmt.Println()
	return string(password), nil
}

// ShowMainMenu displays the main password manager menu.
func ShowMainMenu() {
	clearScreen()
	fmt.Println("==========================================")
	fmt.Println("           Password Manager               ")
	fmt.Println("==========================================")
	fmt.Println("1. Generate new password")
	fmt.Println("2. Add new password")
	fmt.Println("3. Get password")
	fmt.Println("4. List all passwords")
	fmt.Println("5. Update password")
	fmt.Println("6. Delete password")
	fmt.Println("7. List categories")
	fmt.Println("8. Show password statistics")
	fmt.Println("9. Find duplicate passwords")
	fmt.Println("0. Exit")
	fmt.Println("==========================================")
}

// PrintPasswordList displays a formatted list of stored passwords.
func PrintPasswordList(passwords []Password) {
	fmt.Println("=== Password list ===")
	fmt.Printf("%-20s %-15s %-20s %-20s\n",
		"Name",
		"Category",
		"Created",
		"Last Modified",
	)

	fmt.Println("--------------------------------------------------------------------------------")

	for _, password := range passwords {
		fmt.Printf(
			"%-20s %-15s %-20s %-20s\n",
			password.Name,
			password.Category,
			password.CreatedAt.Format("2006-01-02"),
			password.LastModified.Format("2006-01-02"),
		)
	}
}

// ShowPasswordDetails displays detailed information about a stored password.
func ShowPasswordDetails(password Password) {
	fmt.Println("=== Password details ===")
	fmt.Printf(`Service: %s
Category: %s
Password: %s
Created: %s
Last Modified: %s
`, password.Name, password.Category, password.Value, password.CreatedAt.Format("2006-01-02 15:04:05"), password.LastModified.Format("2006-01-02 15:04:05"))
}

// HandlePasswordGeneration handles the password generation flow.
func HandlePasswordGeneration(pm *PasswordManager) error {
	clearScreen()
	fmt.Println("=== Password Generation ===")
	length, err := strconv.Atoi(ReadUserInput("Enter password length (min 8): "))
	if err != nil {
		showError(err.Error())
		return err
	}

	passwd, err := pm.GeneratePassword(length)
	if err != nil {
		showError(err.Error())
		return err
	}
	showSuccess("Password generated successfully")
	fmt.Printf("Generated password: %s", passwd)
	waitForEnter()
	return nil
}

// HandlePasswordAdd handles adding a new password to the password manager.
func HandlePasswordAdd(pm *PasswordManager) error {
	clearScreen()
	fmt.Println("=== Add New Password ===")
	srvName := ReadUserInput("Enter service name: ")
	passwd := ReadUserInput("Enter password (or press Enter to generate):")
	if passwd == "" {
		var err error

		passwd, err = pm.GeneratePassword(12)
		if err != nil {
			showError(err.Error())
			return err
		}
		showInfo(fmt.Sprintf("Generated password: %s", passwd))
	}

	category := ReadUserInput("Enter category: ")
	err := pm.SavePassword(srvName, passwd, category)
	if err != nil {
		showError(err.Error())
		return err
	}

	showSuccess("Password saved successfully")
	waitForEnter()
	return nil
}

// HandlePasswordSearch handles searching for a password by service name.
func HandlePasswordSearch(pm *PasswordManager) error {
	clearScreen()
	fmt.Println("=== Search Password ===")
	srvName := ReadUserInput("Enter service name: ")
	password, err := pm.GetPassword(srvName)
	if err != nil {
		showError(err.Error())
		return err
	}
	showSuccess("Password was find")
	ShowPasswordDetails(password)
	waitForEnter()
	return nil
}

// HandlePasswordUpdate handles updating an existing password.
func HandlePasswordUpdate(pm *PasswordManager) error {
	clearScreen()
	fmt.Println("=== Update Password ===")
	srvName := ReadUserInput("Enter service name: ")
	passwd := ReadUserInput("Enter new password: ")

	err := pm.UpdatePassword(srvName, passwd)
	if err != nil {
		showError(err.Error())
		return err
	}

	showSuccess("Password was updated")
	waitForEnter()
	return nil
}

// HandleExitAndSave saves the password manager data and exits the application.
func HandleExitAndSave(pm *PasswordManager) error {
	clearScreen()
	fmt.Println("=== Saving and Exiting ===")
	fmt.Println("Saving changes...")
	err := pm.SaveToFile()
	if err != nil {
		showError(err.Error())
		return fmt.Errorf("error saving data: %s", err)
	}
	showSuccess("Changes saved successfully!")
	showSuccess("Goodbye!")
	return nil
}

// HandleListPasswords handles displaying all stored passwords.
func HandleListPasswords(pm *PasswordManager) {
	passwords := pm.ListPasswords()
	PrintPasswordList(passwords)
}

// HandleDeletePassword handles deleting a password from the password manager.
func HandleDeletePassword(pm *PasswordManager) error {
	passwdName := ReadUserInput("Enter password name: ")
	if err := pm.DeletePassword(passwdName); err != nil {
		return err
	}
	return nil
}

// HandleListCategories handles displaying all password categories.
func HandleListCategories(pm *PasswordManager) {
	fmt.Println(pm.ListCategories())
}

// HandleGetPasswordStats handles displaying password manager statistics.
func HandleGetPasswordStats(pm *PasswordManager) {
	fmt.Println(pm.GetPasswordStats())
}

// FindDuplicatePasswords displays passwords that are used by multiple services.
func FindDuplicatePasswords(pm *PasswordManager) {
	fmt.Println(pm.FindDuplicatePasswords())
}

func main() {
	pm := NewPasswordManager("ps.dat")
	fmt.Print("Enter master key: ")
	masterKey, err := readPassword()
	if err != nil {
		showError(err.Error())
		return
	}
	err = pm.SetMasterPassword(masterKey)
	if err != nil {
		showError(err.Error())
		return
	}
	showSuccess("Password manager initialized successfully")

	err = pm.LoadFromFile()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		showError(err.Error())
		return
	}

	for {
		ShowMainMenu()
		input := ReadUserInput("Enter your choice:")
		switch input {
		case "1":
			if err := HandlePasswordGeneration(pm); err != nil {
				showError(err.Error())
			}
		case "2":
			if err := HandlePasswordAdd(pm); err != nil {
				showError(err.Error())
			}
		case "3":
			if err := HandlePasswordSearch(pm); err != nil {
				showError(err.Error())
			}
		case "4":
			HandleListPasswords(pm)
		case "5":
			if err := HandlePasswordUpdate(pm); err != nil {
				showError(err.Error())
			}
		case "6":
			if err := HandleDeletePassword(pm); err != nil {
				showError(err.Error())
			}
		case "7":
			HandleListCategories(pm)
		case "8":
			HandleGetPasswordStats(pm)
		case "9":
			FindDuplicatePasswords(pm)
		case "0":
			if err := HandleExitAndSave(pm); err != nil {
				showError(err.Error())
			}
			return
		}
	}
}
