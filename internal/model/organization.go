package model

import (
    "time"
)

type Organization struct {
    Id string `json:"id" db:"id"`
    Name string `json:"name" db:"name"`
    CreatedAt time.Time `json:"createdAt" db:"createdAt"`
}
