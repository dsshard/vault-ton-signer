// internal/usecase/path_read_delete.go

package usecase

import (
    "context"
    "fmt"

    "github.com/hashicorp/vault/sdk/framework"
    "github.com/hashicorp/vault/sdk/logical"
)

// pathReadAndDelete defines endpoints for reading and deleting TON key‑managers.
func pathReadAndDelete(b *Backend) *framework.Path {
    return &framework.Path{
        Pattern:        "key-managers/" + framework.GenericNameRegex("name"),
        ExistenceCheck: b.pathExistenceCheck,
        HelpSynopsis:   "Read or delete a TON key‑manager by name",
        HelpDescription: `
GET     — return the key‑manager details (addresses, public keys)
DELETE  — remove the key‑manager and all its keys by name
        `,
        Fields: map[string]*framework.FieldSchema{
            "name": {Type: framework.TypeString},
        },
        Operations: map[logical.Operation]framework.OperationHandler{
            logical.ReadOperation:   &framework.PathOperation{Callback: b.readKeyManager},
            logical.DeleteOperation: &framework.PathOperation{Callback: b.deleteKeyManager},
        },
    }
}

// readKeyManager handles GET key‑managers/{name}
func (b *Backend) readKeyManager(
    ctx context.Context,
    req *logical.Request,
    data *framework.FieldData,
) (*logical.Response, error) {
    name := data.Get("name").(string)

    km, err := b.retrieveKeyManager(ctx, req, name)
    if err != nil {
        b.Logger().Error("Failed to retrieve key‑manager", "name", name, "error", err)
        return nil, err
    }
    if km == nil {
        return nil, fmt.Errorf("key‑manager %q not found", name)
    }

    // Collect all addresses
    addresses := make([]string, len(km.KeyPairs))
    for i, kp := range km.KeyPairs {
        addresses[i] = kp.Address
    }

    return &logical.Response{
        Data: map[string]interface{}{
            "service_name": km.ServiceName,
            "addresses":    addresses,
        },
    }, nil
}

// deleteKeyManager handles DELETE key‑managers/{name}
func (b *Backend) deleteKeyManager(
    ctx context.Context,
    req *logical.Request,
    data *framework.FieldData,
) (*logical.Response, error) {
    name := data.Get("name").(string)

    km, err := b.retrieveKeyManager(ctx, req, name)
    if err != nil {
        b.Logger().Error("Failed to retrieve key‑manager", "name", name, "error", err)
        return nil, err
    }
    if km == nil {
        // Nothing to delete
        return nil, nil
    }

    // Delete the stored entry
    path := fmt.Sprintf("key-managers/%s", name)
    if err := req.Storage.Delete(ctx, path); err != nil {
        b.Logger().Error("Failed to delete key‑manager", "path", path, "error", err)
        return nil, err
    }
    return nil, nil
}
