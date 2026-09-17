package model

import (
    "time"
)

type Subscription struct {
    Id string `json:"id" db:"id"`
    ClerkOrgId string `json:"clerkOrgId" db:"clerkOrgId"`
    RazorpayCustomerId string `json:"razorpayCustomerId" db:"razorpayCustomerId"`
    RazorpaySubscriptionId string `json:"razorpaySubscriptionId" db:"razorpaySubscriptionId"`
    RazorpayPlanId string `json:"razorpayPlanId" db:"razorpayPlanId"`
    PlanKey string `json:"planKey" db:"planKey"`
    Status string `json:"status" db:"status"`
    CurrentPeriodStart time.Time `json:"currentPeriodStart" db:"currentPeriodStart"`
    CurrentPeriodEnd time.Time `json:"currentPeriodEnd" db:"currentPeriodEnd"`
    CancelAtPeriodEnd bool `json:"cancelAtPeriodEnd" db:"cancelAtPeriodEnd"`
    CancelledAt *time.Time `json:"cancelledAt" db:"cancelledAt"`
    EndedAt *time.Time `json:"endedAt" db:"endedAt"`
    CreatedAt time.Time `json:"createdAt" db:"createdAt"`
    UpdatedAt time.Time `json:"updatedAt" db:"updatedAt"`
}
