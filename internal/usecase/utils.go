// internal/usecase/utils.go
package usecase

import (
    "crypto/ed25519"
    "fmt"

    "github.com/tonkeeper/tongo/wallet"
)

// deriveTonAddress берёт Ed25519 pub‑key и возвращает bounceable‑friendly TON‑адрес.
func deriveTonAddress(pub ed25519.PublicKey) string {
    addr, err := wallet.GenerateWalletAddress(pub, wallet.V4R2, nil, 0, nil)
    if err != nil {
        panic(fmt.Sprintf("deriveTonAddress: %v", err))
    }
    return addr.String()
}

