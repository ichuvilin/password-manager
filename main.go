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
	fmt.Print("Enter name: ")
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

func main() {

}
