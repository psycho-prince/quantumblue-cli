package model

import (
    "time"
)

type PaymentTransaction struct {
    Id string `json:"id" db:"id"`
    ClerkOrgId string `json:"clerkOrgId" db:"clerkOrgId"`
    RazorpayPaymentId string `json:"razorpayPaymentId" db:"razorpayPaymentId"`
    Amount int `json:"amount" db:"amount"`
    Currency string `json:"currency" db:"currency"`
    Status string `json:"status" db:"status"`
    CreatedAt time.Time `json:"createdAt" db:"createdAt"`
    UpdatedAt time.Time `json:"updatedAt" db:"updatedAt"`
}
