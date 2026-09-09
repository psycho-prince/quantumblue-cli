package certificate

import (
	"fmt"
	"strings"
	"time"
)

// GenerateCertificate generates a certificate based on the jurisdiction mode.
func GenerateCertificate(mode string) (string, error) {
	var out strings.Builder
	out.WriteString(fmt.Sprintf("========================================================\n"))
	out.WriteString(fmt.Sprintf("             CRYPTOGRAPHIC INTEGRITY CERTIFICATE        \n"))
	out.WriteString(fmt.Sprintf("========================================================\n"))
	out.WriteString(fmt.Sprintf("Date Issued: %s\n", time.Now().Format(time.RFC3339)))
	
	if mode == "india" {
		out.WriteString("Jurisdiction: India (Indian Evidence Act §65B(4) / Bharatiya Sakshya Adhiniyam §63)\n\n")
		out.WriteString("This certificate confirms that the digital records provided herein\n")
		out.WriteString("were produced by a computer system operating normally and accurately.\n")
		out.WriteString("Cryptographic controls have been applied to ensure the integrity\n")
		out.WriteString("of the electronic record in accordance with statutory requirements.\n")
		out.WriteString("\nSignature:\n________________________\n")
		return out.String(), nil
	} else if mode == "difc" {
		out.WriteString("Jurisdiction: DIFC (RDC Part 29 Witness Statement of Cryptographic Authenticity)\n\n")
		out.WriteString("STATEMENT OF TRUTH\n")
		out.WriteString("I believe that the facts stated in this witness statement are true.\n")
		out.WriteString("I understand that proceedings for contempt of court may be brought\n")
		out.WriteString("against anyone who makes, or causes to be made, a false statement\n")
		out.WriteString("in a document verified by a statement of truth without an honest\n")
		out.WriteString("belief in its truth.\n")
		out.WriteString("\nSignature:\n________________________\n")
		return out.String(), nil
	}
	return "", fmt.Errorf("unsupported certificate mode: %s", mode)
}
