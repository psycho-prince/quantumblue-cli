package model

import (
)

type Finding struct {
    Id string `json:"id" db:"id"`
    ScanId string `json:"scanId" db:"scanId"`
    BomRef string `json:"bomRef" db:"bomRef"`
    Name string `json:"name" db:"name"`
    Primitive string `json:"primitive" db:"primitive"`
    ParameterSetIdentifier *string `json:"parameterSetIdentifier" db:"parameterSetIdentifier"`
    NistQuantumSecurityLevel *int `json:"nistQuantumSecurityLevel" db:"nistQuantumSecurityLevel"`
    Location string `json:"location" db:"location"`
}
