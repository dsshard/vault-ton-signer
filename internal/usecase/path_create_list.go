// internal/usecase/path_create_list.go

package usecase

import (
    "context"
    "crypto/ed25519"
    "crypto/rand"
    "encoding/hex"
    "fmt"
    "regexp"

    "github.com/hashicorp/vault/sdk/framework"
    "github.com/hashicorp/vault/sdk/logical"
)

// pathCreateAndList defines the endpoints for creating/importing
// and listing TON key‑managers.
func pathCreateAndList(b *Backend) *framework.Path {
    return &framework.Path{
        Pattern: "key-managers/?",
        Operations: map[logical.Operation]framework.OperationHandler{
            logical.UpdateOperation: &framework.PathOperation{
                Callback: b.createKeyManager,
            },
            logical.ListOperation: &framework.PathOperation{
                Callback: b.listKeyManagers,
            },
        },
        HelpSynopsis:    "Create or list TON key‑managers",
        HelpDescription: "POST to import or generate a TON ed25519 key; LIST to enumerate all services.",
        Fields: map[string]*framework.FieldSchema{
            "serviceName": {
                Type:        framework.TypeString,
                Description: "Identifier for the key‑manager (e.g. your service name).",
            },
            "privateKey": {
                Type:        framework.TypeString,
                Description: "(Optional) Hex-encoded 32-byte ed25519 seed. If omitted, a new random key is generated.",
                Default:     "",
            },
        },
    }
}

func (b *Backend) listKeyManagers(
    ctx context.Context,
    req *logical.Request,
    data *framework.FieldData,
) (*logical.Response, error) {
    services, err := req.Storage.List(ctx, "key-managers/")
    if err != nil {
        b.Logger().Error("Failed to list key-managers", "error", err)
        return nil, err
    }
    return logical.ListResponse(services), nil
}

func (b *Backend) createKeyManager(
    ctx context.Context,
    req *logical.Request,
    data *framework.FieldData,
) (*logical.Response, error) {
    // serviceName
    svc, ok := data.Get("serviceName").(string)
    if !ok || svc == "" {
        return nil, fmt.Errorf("serviceName must be a non-empty string")
    }
    // optional import
    seedHex, ok := data.Get("privateKey").(string)
    if !ok {
        return nil, fmt.Errorf("privateKey must be a hex string")
    }

    // retrieve or init KeyManager
    km, err := b.retrieveKeyManager(ctx, req, svc)
    if err != nil {
        return nil, err
    }
    if km == nil {
        km = &KeyManager{ServiceName: svc}
    }

    // generate or import ed25519 key
    var seed []byte
    if seedHex != "" {
        re := regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
        if re.FindString(seedHex) == "" {
            return nil, fmt.Errorf("privateKey must be 32-byte hex")
        }
        seed, err = hex.DecodeString(seedHex)
        if err != nil {
            return nil, fmt.Errorf("invalid privateKey hex: %w", err)
        }
    } else {
        seed = make([]byte, ed25519.SeedSize)
        if _, err := rand.Read(seed); err != nil {
            return nil, fmt.Errorf("failed to generate seed: %w", err)
        }
    }
    // derive key pair
    priv := ed25519.NewKeyFromSeed(seed)       // 64-byte private key
    pub := priv.Public().(ed25519.PublicKey)   // 32-byte public key
    defer zeroSeed(seed)                       // wipe seed from memory

    // derive TON address (implement in utils.go)
    addr := deriveTonAddress(pub)

    kp := &KeyPair{
        PrivateKey: hex.EncodeToString(seed),
        PublicKey:  hex.EncodeToString(pub),
        Address:    addr,
    }
    km.KeyPairs = append(km.KeyPairs, kp)

    // store back
    entry, _ := logical.StorageEntryJSON(
        fmt.Sprintf("key-managers/%s", svc),
        km,
    )
    if err := req.Storage.Put(ctx, entry); err != nil {
        b.Logger().Error("Failed to store key-manager", "error", err)
        return nil, err
    }

    return &logical.Response{
        Data: map[string]interface{}{
            "service_name": km.ServiceName,
            "address":      kp.Address,
            "public_key":   kp.PublicKey,
        },
    }, nil
}

// zeroSeed overwrites the seed bytes in memory.
func zeroSeed(b []byte) {
    for i := range b {
        b[i] = 0
    }
}
