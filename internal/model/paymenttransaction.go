package model

import (
    "time"
)

type PaymentTransaction struct {
    Id string `json:"id" db:"id"`
    ClerkOrgId string `json:"clerkOrgId" db:"clerkOrgId"`
    RazorpayPaymentId string `json:"razorpayPaymentId" db:"razorpayPaymentId"`
    RazorpayOrderId *string `json:"razorpayOrderId" db:"razorpayOrderId"`
    RazorpaySubscriptionId *string `json:"razorpaySubscriptionId" db:"razorpaySubscriptionId"`
    Amount int `json:"amount" db:"amount"`
    Currency string `json:"currency" db:"currency"`
    Status string `json:"status" db:"status"`
    Method *string `json:"method" db:"method"`
    Email *string `json:"email" db:"email"`
    CreatedAt time.Time `json:"createdAt" db:"createdAt"`
    UpdatedAt time.Time `json:"updatedAt" db:"updatedAt"`
}
