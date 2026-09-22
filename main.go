package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"time"
)

const (
	lowerLatter = "abcdefghijklmnopqrstuvwxyz"
	upperLatter = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digit       = "0123456789"
	special     = "!@#$%^&*()-_=+[]{}|;:',.<>?/~`"
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

func main() {

}
