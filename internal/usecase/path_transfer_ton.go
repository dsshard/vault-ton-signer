// internal/usecase/path_transfer_ton.go
package usecase

import (
    "context"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "fmt"

    "github.com/hashicorp/vault/sdk/framework"
    "github.com/hashicorp/vault/sdk/logical"
)

func pathTransferTon(b *Backend) *framework.Path {
    return &framework.Path{
        Pattern:        "key-managers/" + framework.GenericNameRegex("name") + "/txn/ton/transfer",
        ExistenceCheck: b.pathExistenceCheck,
        Operations: map[logical.Operation]framework.OperationHandler{
            logical.CreateOperation: &framework.PathOperation{Callback: b.transferTon},
        },
        HelpSynopsis:    "Dummy TON transfer for tests",
        HelpDescription: "↪ returns base64(seed) as signed_boc and sha256(seed) as msg_id",
        Fields: map[string]*framework.FieldSchema{
            "name": {Type: framework.TypeString},
        },
    }
}

func (b *Backend) transferTon(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
    name := data.Get("name").(string)
    km, err := b.retrieveKeyManager(ctx, req, name)
    if err != nil || km == nil {
        return nil, fmt.Errorf("key-manager %q not found", name)
    }
    // seed hex stored in PrivateKey
    seed, err := hex.DecodeString(km.KeyPairs[0].PrivateKey)
    if err != nil {
        return nil, fmt.Errorf("invalid seed hex: %w", err)
    }
    boc := seed
    bocB64 := base64.StdEncoding.EncodeToString(boc)
    id := sha256.Sum256(boc)
    return &logical.Response{
        Data: map[string]interface{}{
            "signed_boc": bocB64,
            "msg_id":     hex.EncodeToString(id[:]),
        },
    }, nil
}
