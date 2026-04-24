package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

var BaseURL = "http://localhost:3000/api"

type Config struct {
	APIKey string `json:"api_key"`
}

func getConfigPath() string {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".quantumblue")
	os.MkdirAll(dir, 0700)
	return filepath.Join(dir, "config.json")
}

func Login(apiKey string) error {
	cfg := Config{APIKey: apiKey}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	err := os.WriteFile(getConfigPath(), data, 0600)
	if err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}
	fmt.Println("✅ Successfully logged in. API Key saved.")
	return nil
}

func GetAPIKey() string {
	data, err := os.ReadFile(getConfigPath())
	if err != nil {
		return ""
	}
	var cfg Config
	json.Unmarshal(data, &cfg)
	return cfg.APIKey
}

func HashFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil))
}

func SyncAsset(filename, filePath string) {
	key := GetAPIKey()
	if key == "" {
		return // Not logged in, skip sync silently
	}

	hash := HashFile(filePath)
	if hash == "" {
		return
	}

	payload := map[string]string{
		"filename":      filename,
		"signatureHash": hash,
	}
	data, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", BaseURL+"/sync", bytes.NewBuffer(data))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("⚠ Warning: Failed to sync with cloud dashboard (Network error)")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("⚠ Warning: Failed to sync with cloud dashboard (Status %d)\n", resp.StatusCode)
	} else {
		fmt.Println("☁️  Asset synced to cloud registry.")
	}
}
