package model

import (
    "time"
)

type Invoice struct {
    Id string `json:"id" db:"id"`
    ClerkOrgId string `json:"clerkOrgId" db:"clerkOrgId"`
    RazorpayInvoiceId *string `json:"razorpayInvoiceId" db:"razorpayInvoiceId"`
    ZohoInvoiceId *string `json:"zohoInvoiceId" db:"zohoInvoiceId"`
    InvoiceNumber *string `json:"invoiceNumber" db:"invoiceNumber"`
    Amount int `json:"amount" db:"amount"`
    Currency string `json:"currency" db:"currency"`
    Status string `json:"status" db:"status"`
    InvoiceUrl *string `json:"invoiceUrl" db:"invoiceUrl"`
    CreatedAt time.Time `json:"createdAt" db:"createdAt"`
    UpdatedAt time.Time `json:"updatedAt" db:"updatedAt"`
}
