package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/psycho-prince/pqc-sdk/internal/audit"
	"github.com/psycho-prince/pqc-sdk/internal/bundle"
	"github.com/psycho-prince/pqc-sdk/internal/cbom"
	"github.com/psycho-prince/pqc-sdk/internal/certificate"
	"github.com/psycho-prince/pqc-sdk/internal/crypto"
	"github.com/psycho-prince/pqc-sdk/internal/scanner"
	"github.com/psycho-prince/pqc-sdk/internal/server"
)

func main() {
	fmt.Println("QuantumBlue CLI v2.0.0-alpha")
	
	if len(os.Args) < 2 {
		fmt.Println("Usage: qb [scan | daemon | cbom | bundle | certificate | crypto-shred | key]")
		return
	}

	switch os.Args[1] {
	case "scan":
		if len(os.Args) < 3 {
			fmt.Println("Usage: qb scan <file.go>")
			return
		}
		s := scanner.NewGoScanner()
		findings, err := s.Scan(os.Args[2])
		if err != nil {
			fmt.Printf("Error scanning file: %v\n", err)
			return
		}
		for _, f := range findings {
			fmt.Printf("Found: %s at %s\n", f.Primitive, f.Location)
		}
	case "daemon":
		if len(os.Args) < 3 {
			fmt.Println("Usage: qb daemon <port>")
			return
		}
		dsn := os.Getenv("DATABASE_URL")
		err := server.StartServer(os.Args[2], dsn)
		if err != nil {
			fmt.Printf("Error starting daemon: %v\n", err)
		}
	case "cbom":
		cbomCmd := flag.NewFlagSet("cbom", flag.ExitOnError)
		target := cbomCmd.String("target", "", "Target directory")
		output := cbomCmd.String("output", "", "Output JSON file")
		cbomCmd.Parse(os.Args[2:])
		if *target == "" || *output == "" {
			fmt.Println("Usage: qb cbom --target <dir> --output <file>")
			return
		}
		
		var allFindings []scanner.CBOMItem
		goScanner := scanner.NewGoScanner()
		confScanner := scanner.NewConfigScanner()
		
		filepath.WalkDir(*target, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if !d.IsDir() {
				if strings.HasSuffix(path, ".go") {
					goF, _ := goScanner.Scan(path)
					allFindings = append(allFindings, goF...)
				} else if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
					confF, _ := confScanner.Scan(path)
					allFindings = append(allFindings, confF...)
				}
			}
			return nil
		})
		
		findingsConverted := []cbom.Finding{}
		for _, f := range allFindings {
			findingsConverted = append(findingsConverted, cbom.Finding{
				Primitive: f.Primitive,
				Location: f.Location,
				Severity: f.Severity,
				Type: f.Type,
				QuantumStatus: f.QuantumStatus,
			})
		}
		
		assets := []cbom.Asset{
			{FilePath: *target, Type: "mixed", Findings: findingsConverted},
		}
		
		c := cbom.NewCBOM(assets)
		data, err := c.ToJSON()
		if err != nil {
			fmt.Printf("CBOM Generation Failed: %v\n", err)
			os.Exit(1)
		}
		
		os.WriteFile(*output, data, 0644)
		fmt.Println("CBOM generated successfully at", *output)
		
	case "bundle":
		bundleCmd := flag.NewFlagSet("bundle", flag.ExitOnError)
		scanID := bundleCmd.String("scan-id", "", "Scan ID")
		output := bundleCmd.String("output", "", "Output PDF file")
		bundleCmd.Parse(os.Args[2:])
		if *scanID == "" || *output == "" {
			fmt.Println("Usage: qb bundle --scan-id=<id> --output=<file>")
			return
		}
		err := bundle.GenerateBundle(*scanID, *output)
		if err != nil {
			fmt.Printf("Failed to generate bundle: %v\n", err)
			return
		}
		fmt.Println("Generated bundle at", *output)

	case "certificate":
		certCmd := flag.NewFlagSet("certificate", flag.ExitOnError)
		mode := certCmd.String("mode", "", "Jurisdiction mode (india/difc)")
		certCmd.Parse(os.Args[2:])
		if *mode == "" {
			fmt.Println("Usage: qb certificate --mode=<mode>")
			return
		}
		res, err := certificate.GenerateCertificate(*mode)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		fmt.Println(res)

	case "crypto-shred":
		shredCmd := flag.NewFlagSet("crypto-shred", flag.ExitOnError)
		keyID := shredCmd.String("key-id", "", "Key ID to shred")
		shredCmd.Parse(os.Args[2:])
		if *keyID == "" {
			fmt.Println("Usage: qb crypto-shred --key-id=<id>")
			return
		}
		provider := crypto.NewFileKeyProvider(".")
		err := provider.Destroy(*keyID)
		if err != nil {
			fmt.Printf("Error shredding key: %v\n", err)
			return
		}
		
		auditLogger, err := audit.NewAuditLogger("audit.log")
		if err == nil {
			auditLogger.LogEvent("crypto_shred", fmt.Sprintf("Key ID %s shredded", *keyID))
		}
		
		hash := sha256.Sum256([]byte(*keyID + time.Now().String()))
		cert := fmt.Sprintf("ERASURE CERTIFICATE\nKey ID: %s\nTime: %s\nHash: %s", *keyID, time.Now().Format(time.RFC3339), hex.EncodeToString(hash[:]))
		fmt.Println(cert)

	case "key":
		if len(os.Args) < 3 {
			fmt.Println("Usage: qb key show --key-id=<id>")
			return
		}
		if os.Args[2] == "show" {
			showCmd := flag.NewFlagSet("show", flag.ExitOnError)
			keyID := showCmd.String("key-id", "", "ID of the key to show")
			showCmd.Parse(os.Args[3:])
			
			if *keyID == "" {
				fmt.Println("Usage: qb key show --key-id=<id>")
				return
			}
			
			provider := crypto.NewFileKeyProvider(".")
			keyData, err := provider.Show(*keyID)
			if err != nil {
				fmt.Printf("Error showing key: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Key Data: %x\n", keyData)
		} else {
			fmt.Println("Unknown key subcommand")
		}
	default:
		fmt.Println("Unknown command")
	}
}
