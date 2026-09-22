package reporter

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/jung-kurt/gofpdf"
	"github.com/psycho-prince/pqc-sdk/internal/graph"
	"github.com/psycho-prince/pqc-sdk/internal/model"
)

type PDFReporter struct {
	graph *graph.GraphStore
}

func NewPDFReporter(g *graph.GraphStore) *PDFReporter {
	return &PDFReporter{graph: g}
}

func (r *PDFReporter) Generate(ctx context.Context, orgID string, assets []model.Asset) ([]byte, error) {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetFont("Helvetica", "", 10)
	pdf.AddPage()

	// Header
	pdf.SetFont("Helvetica", "B", 16)
	pdf.Cell(0, 10, "QuantumBlue Security Assessment Report")
	pdf.Ln(14)

	pdf.SetFont("Helvetica", "", 10)
	pdf.Cell(0, 6, fmt.Sprintf("Organization ID: %s", orgID))
	pdf.Ln(7)
	pdf.Cell(0, 6, fmt.Sprintf("Report Generated: %s", time.Now().UTC().Format(time.RFC3339)))
	pdf.Ln(7)
	pdf.Cell(0, 6, "Assessment performed by QuantumBlue based on the selected assessment scope and methodology.")
	pdf.Ln(12)

	// Disclaimer
	pdf.SetFont("Helvetica", "I", 8)
	pdf.MultiCell(0, 4, "This assessment reflects QuantumBlue's analysis of observed cryptographic configurations at the time of assessment. It does not constitute a legal opinion, government certification, or guarantee of regulatory compliance.", "", "", false)
	pdf.Ln(8)

	// Asset summary
	pdf.SetFont("Helvetica", "B", 12)
	pdf.Cell(0, 8, "Asset Summary")
	pdf.Ln(12)

	pdf.SetFont("Helvetica", "", 10)
	if len(assets) == 0 {
		pdf.Cell(0, 6, "No assets found in scope.")
		pdf.Ln(10)
	} else {
		pdf.SetFont("Helvetica", "B", 9)
		pdf.Cell(10, 6, "#")
		pdf.Cell(25, 6, "Kind")
		pdf.Cell(50, 6, "Identifier")
		pdf.Cell(25, 6, "Criticality")
		pdf.Cell(30, 6, "First Seen")
		pdf.Ln(8)

		pdf.SetFont("Helvetica", "", 9)
		for i, a := range assets {
			if i >= 50 {
				pdf.SetFont("Helvetica", "I", 8)
				pdf.Cell(0, 5, fmt.Sprintf("... and %d more assets (truncated)", len(assets)-50))
				pdf.Ln(8)
				break
			}
			pdf.Cell(10, 5, fmt.Sprintf("%d", i+1))
			pdf.Cell(25, 5, truncate(a.Kind, 20))
			pdf.Cell(50, 5, truncate(a.Identifier, 45))
			pdf.Cell(25, 5, truncate(a.Criticality, 20))
			pdf.Cell(30, 5, a.FirstSeenAt.Format("2006-01-02"))
			pdf.Ln(6)
		}
	}

	pdf.Ln(8)

	// Crypto inventory summary
	pdf.SetFont("Helvetica", "B", 12)
	pdf.Cell(0, 8, "Cryptographic Inventory Summary")
	pdf.Ln(12)

	pdf.SetFont("Helvetica", "", 10)
	pdf.Cell(0, 6, fmt.Sprintf("Total assets in scope: %d", len(assets)))
	pdf.Ln(7)
	pdf.Cell(0, 6, "Note: Detailed cryptographic primitive inventory requires scanning results (CryptoUse records).")
	pdf.Ln(12)

	// Footer
	pdf.SetFont("Helvetica", "I", 8)
	pdf.MultiCell(0, 4, "For questions about this assessment, contact: https://quantum-blue.in/contact", "", "", false)
	pdf.Ln(6)
	pdf.SetFont("Helvetica", "B", 9)
	pdf.Cell(0, 5, "QuantumBlue Security Assessment Certificate")
	pdf.Ln(7)
	pdf.SetFont("Helvetica", "", 9)
	pdf.Cell(0, 5, "Signature: ________________________")
	pdf.Ln(6)

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("pdf generation failed: %w", err)
	}
	return buf.Bytes(), nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
