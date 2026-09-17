package model

import (
    "time"
)

type BillingCustomer struct {
    Id string `json:"id" db:"id"`
    ClerkOrgId string `json:"clerkOrgId" db:"clerkOrgId"`
    RazorpayCustomerId string `json:"razorpayCustomerId" db:"razorpayCustomerId"`
    Email string `json:"email" db:"email"`
    Name string `json:"name" db:"name"`
    CreatedAt time.Time `json:"createdAt" db:"createdAt"`
    UpdatedAt time.Time `json:"updatedAt" db:"updatedAt"`
}
