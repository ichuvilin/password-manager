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

type Password struct {
	Name         string    `json:"name"`
	Value        string    `json:"value"`
	Category     string    `json:"category"`
	CreatedAt    time.Time `json:"created_at"`
	LastModified time.Time `json:"last_modified"`
}

type PasswordManager struct {
	passwords     map[string]Password `json:"passwords"`
	masterKey     []byte              `json:"-"`
	filePath      string              `json:"-"`
	isInitialized bool                `json:"-"`
}

func NewPasswordManager(filePath string) *PasswordManager {
	return &PasswordManager{
		passwords:     make(map[string]Password),
		filePath:      filePath,
		isInitialized: false,
	}
}

func NewPassword(name, value, category string) Password {
	return Password{Name: name, Value: value, Category: category, CreatedAt: time.Now(), LastModified: time.Now()}
}

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

func (pm *PasswordManager) ListPasswords() []Password {
	passwords := make([]Password, 0, len(pm.passwords))

	for _, v := range pm.passwords {
		passwords = append(passwords, v)
	}

	return passwords
}

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

func (pm *PasswordManager) GetPasswordsByCategory(category string) []Password {
	result := make([]Password, 0)

	for _, p := range pm.passwords {
		if strings.ToLower(p.Category) == strings.ToLower(category) {
			result = append(result, p)
		}
	}

	return result
}

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

func clearScreen() {
	fmt.Print("\033[H\033[2J")
}

func showSuccess(message string) {
	fmt.Printf("%s✓ Success: %s%s\n", colorGreen, message, colorReset)
}

func showError(message string) {
	fmt.Printf("%s✗ Error: %s%s\n", colorRed, message, colorReset)
}

func showInfo(message string) {
	fmt.Printf("%s→ Info: %s%s\n", colorYellow, message, colorReset)
}

func waitForEnter() {
	fmt.Print("\nPress Enter to continue...")

	reader := bufio.NewReader(os.Stdin)
	_, _ = reader.ReadString('\n')
}

func ReadUserInput(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func readPassword() (string, error) {
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	fmt.Println()
	return string(password), nil
}

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

func ShowPasswordDetails(password Password) {
	fmt.Println("=== Password details ===")
	fmt.Printf(`Service: %s
Category: %s
Password: %s
Created: %s
Last Modified: %s
`, password.Name, password.Category, password.Value, password.CreatedAt.Format("2006-01-02 15:04:05"), password.LastModified.Format("2006-01-02 15:04:05"))
}

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

func HandleListPasswords(pm *PasswordManager) {
	passwords := pm.ListPasswords()
	PrintPasswordList(passwords)
}

func HandleDeletePassword(pm *PasswordManager) error {
	passwdName := ReadUserInput("Enter password name: ")
	if err := pm.DeletePassword(passwdName); err != nil {
		return err
	}
	return nil
}

func HandleListCategories(pm *PasswordManager) {
	fmt.Println(pm.ListCategories())
}

func HandleGetPasswordStats(pm *PasswordManager) {
	fmt.Println(pm.GetPasswordStats())
}

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
