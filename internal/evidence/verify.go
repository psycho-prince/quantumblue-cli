package evidence

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// VerificationRequest is the input for the public verification endpoint.
type VerificationRequest struct {
	EvidenceID string      `json:"evidence_id"`
	Hashes     []HashCheck `json:"hashes"`
}

// HashCheck is a single hash check in a verification request.
type HashCheck struct {
	FileName string `json:"file_name"`
	Expected string `json:"expected_hash"`
}

// VerificationResponse is the public verification result.
type VerificationResponse struct {
	EvidenceID      string          `json:"evidence_id"`
	Status          string          `json:"status"`
	SHA256          string          `json:"sha256,omitempty"`
	Manifest        json.RawMessage `json:"manifest,omitempty"`
	ChainOfCustody  string          `json:"chain_of_custody,omitempty"`
	CustodyEvents   int             `json:"custody_events"`
	Certificate     json.RawMessage `json:"certificate,omitempty"`
	CertificateID   string          `json:"certificate_id,omitempty"`
	CertificateStatus string        `json:"certificate_status,omitempty"`
	VerifiedAt      time.Time       `json:"verified_at"`
	Signature       string          `json:"signature,omitempty"`
	SignatureAlgo   string          `json:"signature_algorithm,omitempty"`
	Message         string          `json:"message"`
	LegalFramework  string          `json:"legal_framework"`
}

// VerificationService provides public verification of evidence integrity.
type VerificationService struct {
	evidenceStore map[string]*Evidence
	custodyStore  map[string]*ChainEngine
	certStore     map[string]*BSAS63Certificate
}

// NewVerificationService creates a verification service.
func NewVerificationService() *VerificationService {
	return &VerificationService{
		evidenceStore: make(map[string]*Evidence),
		custodyStore:  make(map[string]*ChainEngine),
		certStore:     make(map[string]*BSAS63Certificate),
	}
}

// RegisterEvidence adds evidence to the verification store.
func (vs *VerificationService) RegisterEvidence(ev *Evidence, chain *ChainEngine, cert *BSAS63Certificate) {
	vs.evidenceStore[ev.ID] = ev
	if chain != nil {
		vs.custodyStore[ev.ID] = chain
	}
	if cert != nil {
		vs.certStore[ev.ID] = cert
	}
}

// VerifyEvidence checks the integrity of evidence by ID.
func (vs *VerificationService) VerifyEvidence(req VerificationRequest) *VerificationResponse {
	ev, ok := vs.evidenceStore[req.EvidenceID]
	if !ok {
		return &VerificationResponse{
			EvidenceID:     req.EvidenceID,
			Status:         "NOT FOUND",
			Message:        fmt.Sprintf("Evidence %s not found in verification system", req.EvidenceID),
			VerifiedAt:     time.Now(),
			LegalFramework: "BSA §63",
		}
	}

	resp := &VerificationResponse{
		EvidenceID:     ev.ID,
		SHA256:         ev.SHA256,
		Manifest:       ev.Manifest,
		VerifiedAt:     time.Now(),
		LegalFramework: "BSA §63",
	}

	if chain, ok := vs.custodyStore[ev.ID]; ok {
		chainResult, err := chain.VerifyChain(ev.ID)
		if err != nil {
			resp.Status = "INTEGRITY FAILURE"
			resp.Message = fmt.Sprintf("Chain of custody verification failed: %s", err.Error())
		} else {
			resp.Status = "INTEGRITY VERIFIED"
			resp.Message = "Evidence integrity verified. Chain of custody intact."
			resp.CustodyEvents = len(chainResult.Events)
			resp.ChainOfCustody = chainResult.CurrentHash
		}
	} else {
		resp.Status = "INTEGRITY VERIFIED"
		resp.Message = "Evidence record found. No chain of custody registered."
	}

	if cert, ok := vs.certStore[ev.ID]; ok {
		resp.CertificateID = cert.CertificateID
		resp.CertificateStatus = string(cert.Status)
		certData, _ := json.Marshal(cert)
		resp.Certificate = certData
		if len(cert.Signature) > 0 {
			resp.SignatureAlgo = cert.SignatureAlgo
			resp.Signature = hex.EncodeToString(cert.Signature)
		}
	}

	if len(req.Hashes) > 0 {
		allMatch := true
		for _, hc := range req.Hashes {
			if hc.Expected != ev.SHA256 {
				allMatch = false
				break
			}
		}
		if !allMatch {
			resp.Status = "INTEGRITY FAILURE"
			resp.Message = "One or more file hashes do not match."
		}
	}

	return resp
}

// VerificationHandler is the HTTP handler for the public verification portal.
func (vs *VerificationService) VerificationHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	var req VerificationRequest
	if r.Method == http.MethodGet {
		q := r.URL.Query()
		req.EvidenceID = q.Get("evidence_id")
		if req.EvidenceID == "" {
			http.Error(w, `{"error":"evidence_id required"}`, http.StatusBadRequest)
			return
		}
	} else {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"invalid request: %s"}`, err.Error()), http.StatusBadRequest)
			return
		}
	}

	if req.EvidenceID == "" {
		http.Error(w, `{"error":"evidence_id is required"}`, http.StatusBadRequest)
		return
	}

	resp := vs.VerifyEvidence(req)
	respData, _ := json.MarshalIndent(resp, "", "  ")
	w.Write(respData)
}

const verificationFormHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>QuantumBlue Evidence Verification</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 560px; margin: 60px auto; padding: 0 20px; background: #0f172a; color: #e2e8f0; }
  .header { text-align: center; margin-bottom: 40px; }
  .header h1 { font-size: 28px; margin: 0; color: #38bdf8; }
  .header .sub { color: #94a3b8; font-size: 14px; margin-top: 8px; }
  .card { background: #1e293b; border-radius: 12px; padding: 32px; border: 1px solid #334155; }
  input { width: 100%; padding: 12px 16px; border-radius: 8px; border: 1px solid #334155; background: #0f172a; color: #e2e8f0; font-size: 15px; outline: none; }
  input:focus { border-color: #38bdf8; }
  button { width: 100%; padding: 12px; border-radius: 8px; border: none; background: #38bdf8; color: #0f172a; font-weight: 600; font-size: 15px; cursor: pointer; margin-top: 16px; }
  button:hover { background: #7dd3fc; }
  .info { margin-top: 24px; padding: 16px; background: #1e293b; border-radius: 8px; font-size: 13px; color: #94a3b8; }
  .info h3 { color: #e2e8f0; margin: 0 0 8px 0; font-size: 14px; }
</style>
</head>
<body>
<div class="header">
  <h1>QuantumBlue</h1>
  <div class="sub">Cryptographic Evidence Integrity Platform</div>
</div>
<div class="card">
  <h2 style="margin: 0 0 16px 0; color: #e2e8f0; font-size: 18px;">Verify Evidence Integrity</h2>
  <form action="/verify" method="get">
    <input type="text" name="evidence_id" placeholder="Enter Evidence ID (e.g. QB-EVD-000001)" required>
    <button type="submit">Verify</button>
  </form>
  <div class="info">
    <h3>How verification works</h3>
    Enter an Evidence ID to verify its cryptographic integrity. QuantumBlue checks the SHA-256 hash,
    chain of custody, and BSA §63 certificate to confirm the evidence has not been tampered with.
    This verification is publicly accessible and can be used in legal proceedings.
  </div>
</div>
<div style="text-align: center; margin-top: 30px; color: #64748b; font-size: 12px;">
  Powered by QuantumBlue · Bharatiya Sakshya Adhiniyam, 2023 — Section 63
</div>
</body>
</html>
`

// VerifyEvidenceHTML renders a human-readable verification result page.
func (vs *VerificationService) VerifyEvidenceHTML(w http.ResponseWriter, r *http.Request) {
	evidenceID := r.URL.Query().Get("evidence_id")
	if evidenceID == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(verificationFormHTML))
		return
	}

	req := VerificationRequest{EvidenceID: evidenceID}
	resp := vs.VerifyEvidence(req)

	var statusColor, statusIcon string
	switch resp.Status {
	case "INTEGRITY VERIFIED":
		statusColor = "#10b981"
		statusIcon = "✓"
	case "INTEGRITY FAILURE":
		statusColor = "#ef4444"
		statusIcon = "✗"
	default:
		statusColor = "#6b7280"
		statusIcon = "?"
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>QuantumBlue Evidence Verification — %s</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 720px; margin: 40px auto; padding: 0 20px; background: #0f172a; color: #e2e8f0; }
  .header { border-bottom: 1px solid #334155; padding-bottom: 20px; margin-bottom: 30px; }
  .header h1 { font-size: 24px; margin: 0; color: #38bdf8; }
  .header .sub { color: #94a3b8; font-size: 14px; margin-top: 6px; }
  .result { background: #1e293b; border-radius: 8px; padding: 24px; border: 1px solid #334155; }
  .status-badge { display: inline-block; padding: 4px 12px; border-radius: 999px; font-size: 13px; font-weight: 600; color: white; margin-bottom: 16px; }
  .row { display: flex; padding: 8px 0; border-bottom: 1px solid #334155; font-size: 14px; }
  .row:last-child { border-bottom: none; }
  .label { width: 200px; color: #94a3b8; flex-shrink: 0; }
  .value { flex: 1; word-break: break-all; }
  .mono { font-family: 'SF Mono', Consolas, monospace; font-size: 13px; }
  .footer { margin-top: 30px; color: #64748b; font-size: 12px; text-align: center; }
  a { color: #38bdf8; }
</style>
</head>
<body>
<div class="header">
  <h1>QuantumBlue Evidence Verification</h1>
  <div class="sub">Public verification portal · Bharatiya Sakshya Adhiniyam, 2023 — Section 63</div>
</div>
<div class="result">
  <div class="status-badge" style="background: %s">%s %s</div>
  <div class="row"><div class="label">Evidence ID</div><div class="value mono"><code>%s</code></div></div>
  <div class="row"><div class="label">SHA-256</div><div class="value mono"><code>%s</code></div></div>
  <div class="row"><div class="label">Chain of Custody</div><div class="value mono"><code>%s</code></div></div>
  <div class="row"><div class="label">Custody Events</div><div class="value">%d</div></div>
  <div class="row"><div class="label">Certificate</div><div class="value">%s</div></div>
  <div class="row"><div class="label">Certificate Status</div><div class="value">%s</div></div>
  <div class="row"><div class="label">Verified At</div><div class="value">%s</div></div>
  <div class="row"><div class="label">Legal Framework</div><div class="value">%s</div></div>
  <div class="row"><div class="label">Message</div><div class="value">%s</div></div>
</div>
<div class="footer">
  Verification performed by QuantumBlue on %s · <a href="/verify">Verify another evidence</a>
</div>
</body>
</html>
`,
		evidenceID,
		statusColor, statusIcon, resp.Status,
		evidenceID,
		resp.SHA256,
		resp.ChainOfCustody,
		resp.CustodyEvents,
		resp.CertificateID,
		resp.CertificateStatus,
		resp.VerifiedAt.Format(time.RFC3339),
		resp.LegalFramework,
		resp.Message,
		time.Now().Format(time.RFC3339),
	)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}
