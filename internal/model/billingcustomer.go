package model

import (
    "time"
)

type BillingCustomer struct {
    Id string `json:"id" db:"id"`
    ClerkOrgId string `json:"clerkOrgId" db:"clerkOrgId"`
    ClerkUserId *string `json:"clerkUserId" db:"clerkUserId"`
    RazorpayCustomerId string `json:"razorpayCustomerId" db:"razorpayCustomerId"`
    ZohoCustomerId *string `json:"zohoCustomerId" db:"zohoCustomerId"`
    Email string `json:"email" db:"email"`
    Name string `json:"name" db:"name"`
    CreatedAt time.Time `json:"createdAt" db:"createdAt"`
    UpdatedAt time.Time `json:"updatedAt" db:"updatedAt"`
}
