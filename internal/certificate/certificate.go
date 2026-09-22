package certificate

import (
	"fmt"
	"strings"
	"time"
)

// GenerateCertificate generates a QuantumBlue Security Assessment Certificate.
// It does not imply government certification, legal evidentiary status, or
// regulatory compliance — it reflects QuantumBlue's analysis of observed
// cryptographic configurations at the time of assessment.
func GenerateCertificate(mode string) (string, error) {
	var out strings.Builder
	out.WriteString(fmt.Sprintf("========================================================\n"))
	out.WriteString(fmt.Sprintf("        QUANTUMBLUE SECURITY ASSESSMENT CERTIFICATE       \n"))
	out.WriteString(fmt.Sprintf("========================================================\n"))
	out.WriteString(fmt.Sprintf("Date Issued: %s\n", time.Now().Format(time.RFC3339)))
	out.WriteString(fmt.Sprintf("Assessment performed by QuantumBlue based on the selected\n"))
	out.WriteString(fmt.Sprintf("assessment scope and methodology.\n\n"))

	out.WriteString(fmt.Sprintf("Scope: Cryptographic inventory and quantum vulnerability assessment\n"))
	out.WriteString(fmt.Sprintf("Target: %s\n", mode))
	out.WriteString(fmt.Sprintf("Methodology: QuantumBlue policy rules + discovery scope\n\n"))

	out.WriteString("This assessment reflects QuantumBlue's analysis of observed cryptographic\n")
	out.WriteString("configurations at the time of assessment. It does not constitute a legal\n")
	out.WriteString("opinion, government certification, or guarantee of regulatory compliance.\n")
	out.WriteString("\n")
	out.WriteString("For questions about this assessment, contact: https://quantum-blue.in/contact\n")
	out.WriteString("\nSignature:\n________________________\n")
	return out.String(), nil
}
