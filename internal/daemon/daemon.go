package daemon

import (
	"log"
	"path/filepath"
	"strings"

	"github.com/fsnotify/fsnotify"
	"github.com/psycho-prince/pqc-sdk/internal/crypto"
	"github.com/psycho-prince/pqc-sdk/internal/api"
)

// Config holds the daemon settings.
type Config struct {
	WatchDir      string
	PublicKeyKEM  []byte
	PrivateKeyDSA []byte
	ClassicSecret []byte
}

// Start watching the directory for new source files to auto-seal and sign.
func Start(cfg Config) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()

	done := make(chan bool)
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
					handleFileEvent(event.Name, cfg)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Println("Watcher error:", err)
			}
		}
	}()

	err = watcher.Add(cfg.WatchDir)
	if err != nil {
		return err
	}
	log.Printf("🧿 QuantumBlue Notary Daemon monitoring: %s\n", cfg.WatchDir)
	<-done
	return nil
}

func handleFileEvent(path string, cfg Config) {
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".pqc" || ext == ".decrypted" {
		return
	}

	// Filter for sensitive assets
	if ext == ".ts" || ext == ".py" || ext == ".sol" || ext == ".env" || ext == ".bin" {
		outPath := path + ".pqc"
		log.Printf("🛡️  Signing & Sealing: %s\n", filepath.Base(path))
		err := crypto.SealSignedStream(path, outPath, cfg.PublicKeyKEM, cfg.PrivateKeyDSA, cfg.ClassicSecret)
		if err != nil {
			log.Printf("❌ Notary failed for %s: %v\n", path, err)
		} else {
			go api.SyncAsset(filepath.Base(path), outPath)
		}
	}
}
