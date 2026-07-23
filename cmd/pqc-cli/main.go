package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/psycho-prince/pqc-sdk/internal/crypto"
	"github.com/psycho-prince/pqc-sdk/internal/daemon"
	"github.com/psycho-prince/pqc-sdk/internal/api"
	"github.com/psycho-prince/pqc-sdk/internal/audit"
	"github.com/psycho-prince/pqc-sdk/internal/transform"
	"github.com/psycho-prince/pqc-sdk/internal/rag"
	"github.com/psycho-prince/pqc-sdk/internal/orchestrator"
	"github.com/psycho-prince/pqc-sdk/internal/analyzer"
	"context"
)

func main() {
	mode := flag.String("mode", "seal", "Operation mode: seal, unseal, identity, daemon, login, analyze, or migrate")
	file := flag.String("file", "", "Target file path")
	apiKey := flag.String("api-key", "", "API Key for login")
	skKEM := flag.String("sk-kem", "pqc.sk", "KEM Private key file")
	pkKEM := flag.String("pk-kem", "pqc.pk", "KEM Public key file")
	skDSA := flag.String("sk-dsa", "id.sk", "DSA Private key file (Identity)")
	pkDSA := flag.String("pk-dsa", "id.pk", "DSA Public key file (Identity)")
	watchDir := flag.String("watch", ".", "Directory to monitor in daemon mode")
	targetDir := flag.String("target", ".", "Directory to analyze or migrate")
	flag.Parse()

	classicSecret := []byte("X25519-HYBRID-SECRET-2026")

	// Initialize Audit Logger
	auditLogger, err := audit.NewAuditLogger("quantumblue.audit")
	if err != nil {
		log.Fatalf("Failed to initialize audit logger: %v", err)
	}

	// Initialize PQC Pipeline components
	// aiClient := ai.NewOpenAIClient() // REPLACED
	transformer := transform.NewRuleBasedTransformer()
	vectorStore, _ := rag.NewVectorStore("pqc.db")
	pipeline := &orchestrator.Pipeline{Transformer: transformer}
	defer vectorStore.Close()

	switch *mode {
	case "login":
		if *apiKey == "" {
			log.Fatal("-api-key is required for login")
		}
		if err := api.Login(*apiKey); err != nil {
			log.Fatalf("Login failed: %v", err)
		}

	case "identity":
		pk, sk, _ := crypto.GenerateIdentityKeyPair()
		os.WriteFile(*pkDSA, pk, 0644)
		os.WriteFile(*skDSA, sk, 0600)
		auditLogger.LogEvent("IDENTITY_GEN", fmt.Sprintf("Identity keys generated: %s, %s", *pkDSA, *skDSA))
		fmt.Printf("🧿 ML-DSA-65 Identity Generated: %s, %s\n", *pkDSA, *skDSA)

	case "seal":
		if *file == "" { log.Fatal("-file is required") }
		pkK, skK, _ := crypto.GenerateKyberKeyPair()
		os.WriteFile(*pkKEM, pkK, 0644)
		os.WriteFile(*skKEM, skK, 0600)
		skD, err := os.ReadFile(*skDSA)
		if err != nil { log.Fatal("Missing identity key. Run -mode=identity first.") }
		out := *file + ".pqc"
		err = crypto.SealSignedStream(*file, out, pkK, skD, classicSecret)
		if err != nil { 
			auditLogger.LogEvent("SEAL_FAIL", fmt.Sprintf("File: %s, Error: %v", *file, err))
			log.Fatalf("Seal failed: %v", err) 
		}
		auditLogger.LogEvent("SEAL_SUCCESS", fmt.Sprintf("File: %s, Out: %s", *file, out))
		fmt.Printf("🔒 Signed & Sealed: %s\n", out)
		go api.SyncAsset(*file, out)

	case "unseal":
		if *file == "" { log.Fatal("-file is required") }
		skK, _ := os.ReadFile(*skKEM)
		pkD, _ := os.ReadFile(*pkDSA)
		out := *file + ".decrypted"
		err := crypto.UnsealSignedStream(*file, out, skK, pkD, classicSecret)
		if err != nil { 
			auditLogger.LogEvent("UNSEAL_FAIL", fmt.Sprintf("File: %s, Error: %v", *file, err))
			log.Fatalf("Unseal failed: %v", err) 
		}
		auditLogger.LogEvent("UNSEAL_SUCCESS", fmt.Sprintf("File: %s, Out: %s", *file, out))
		fmt.Printf("🔓 Verified & Decrypted: %s\n", out)

	case "daemon":
		runDaemon(*watchDir, *pkKEM, *skDSA, classicSecret)

	case "analyze":
		fmt.Printf("🔍 Generating inventory for: %s\n", *targetDir)
		inventory, err := analyzer.GenerateInventory(*targetDir)
		if err != nil {
			log.Fatalf("Inventory generation failed: %v", err)
		}
		
		err = analyzer.ExportInventory(inventory, "inventory.json")
		if err != nil {
			log.Fatalf("Export failed: %v", err)
		}
		fmt.Println("✅ Inventory exported to inventory.json")

	case "migrate":
		fmt.Printf("🚀 Migrating target: %s to PQC\n", *targetDir)
		pipeline.RunMigration(context.Background(), *targetDir)

	default:
		fmt.Printf("Unknown mode: %s\n", *mode)
		flag.Usage()
	}
}

func runDaemon(dir, pkKEMFile, skDSAFile string, classicSecret []byte) {
	// 1. Load or generate KEM public key for sealing
	pkK, err := os.ReadFile(pkKEMFile)
	if err != nil {
		fmt.Println("⚠ No public vault key found. Generating a new one for auto-sealing...")
		var skK []byte
		pkK, skK, _ = crypto.GenerateKyberKeyPair()
		os.WriteFile(pkKEMFile, pkK, 0644)
		os.WriteFile("pqc.sk", skK, 0600)
		fmt.Println("🔑 Vault Keys generated: pqc.pk, pqc.sk")
	}

	// 2. Load or generate DSA identity key for signing
	skD, err := os.ReadFile(skDSAFile)
	if err != nil {
		fmt.Println("⚠ No identity key found. Generating a new one for the notary...")
		var pkD []byte
		pkD, skD, _ = crypto.GenerateIdentityKeyPair()
		os.WriteFile("id.pk", pkD, 0644)
		os.WriteFile(skDSAFile, skD, 0600)
		fmt.Println("🧿 Identity Keys generated: id.pk, id.sk")
	}

	cfg := daemon.Config{
		WatchDir:      dir,
		PublicKeyKEM:  pkK,
		PrivateKeyDSA: skD,
		ClassicSecret: classicSecret,
	}

	if err := daemon.Start(cfg); err != nil {
		log.Fatalf("Daemon failed: %v", err)
	}
}
