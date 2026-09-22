package main

import (
	"crypto/rand"
	"errors"
	"time"
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:',.<>?/~`"

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

	password := make([]byte, length)

	for i, b := range buf {
		password[i] = charset[int(b)%len(charset)]
	}

	return string(password), nil
}

func main() {

}
