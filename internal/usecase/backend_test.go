// internal/usecase/backend_test.go

package usecase

import (
    "context"
    "crypto/sha256"
    "encoding/base64"
    "crypto/ed25519"
    "encoding/hex"
    "testing"

    "github.com/hashicorp/vault/sdk/logical"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// newTestBackend возвращает Backend с in-memory сториджем для тестов.
func newTestBackend(t *testing.T) (*Backend, logical.Storage) {
    t.Helper()
    storage := &logical.InmemStorage{}
    b, err := Factory(context.Background(), &logical.BackendConfig{
        StorageView: storage,
    })
    if err != nil {
        t.Fatalf("Factory error: %v", err)
    }
    be, ok := b.(*Backend)
    if !ok {
        t.Fatalf("unexpected backend type: %T", b)
    }
    return be, storage
}

func TestCreateAndListKeyManagers(t *testing.T) {
    b, storage := newTestBackend(t)

    // 1) Импорт seed
    req := logical.TestRequest(t, logical.UpdateOperation, "key-managers")
    req.Storage = storage
    req.Data = map[string]interface{}{
        "serviceName": "svc",
        "privateKey":  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    }
    resp, err := b.HandleRequest(context.Background(), req)
    require.NoError(t, err)
    addr := resp.Data["address"].(string)
    require.NotEmpty(t, addr)

    // 2) Генерация ещё одного ключа
    req = logical.TestRequest(t, logical.UpdateOperation, "key-managers")
    req.Storage = storage
    req.Data = map[string]interface{}{"serviceName": "svc"}
    _, err = b.HandleRequest(context.Background(), req)
    require.NoError(t, err)

    // 3) List
    req = logical.TestRequest(t, logical.ListOperation, "key-managers")
    req.Storage = storage
    resp, err = b.HandleRequest(context.Background(), req)
    require.NoError(t, err)
    services := resp.Data["keys"].([]string)
    assert.Equal(t, []string{"svc"}, services)

    // 4) Read and check two addresses
    req = logical.TestRequest(t, logical.ReadOperation, "key-managers/svc")
    req.Storage = storage
    resp, err = b.HandleRequest(context.Background(), req)
    require.NoError(t, err)
    addrs := resp.Data["addresses"].([]string)
    assert.Len(t, addrs, 2)
    assert.Contains(t, addrs, addr)
}

func TestSignHash(t *testing.T) {
    b, storage := newTestBackend(t)

    // Create manager
    req := logical.TestRequest(t, logical.UpdateOperation, "key-managers")
    req.Storage = storage
    req.Data = map[string]interface{}{"serviceName": "svc"}
    _, err := b.HandleRequest(context.Background(), req)
    require.NoError(t, err)

    // Sign zero‑hash
    zeroHash := hex.EncodeToString(make([]byte, 32))
    req = logical.TestRequest(t, logical.CreateOperation, "key-managers/svc/sign")
    req.Storage = storage
    req.Data = map[string]interface{}{
        "name": "svc",
        "hash": zeroHash,
    }
    resp, err := b.HandleRequest(context.Background(), req)
    require.NoError(t, err)
    sigHex := resp.Data["signature"].(string)
    sig, err := hex.DecodeString(sigHex)
    require.NoError(t, err)
    assert.Len(t, sig, ed25519.SignatureSize)
}

func TestTransferTon(t *testing.T) {
    b, storage := newTestBackend(t)

    // Create manager
    req := logical.TestRequest(t, logical.UpdateOperation, "key-managers")
    req.Storage = storage
    req.Data = map[string]interface{}{"serviceName": "svc"}
    resp, err := b.HandleRequest(context.Background(), req)
    require.NoError(t, err)
    addr := resp.Data["address"].(string)
    require.NotEmpty(t, addr)

    // Dummy TON transfer: returns seed as BOC
    req = logical.TestRequest(t, logical.CreateOperation, "key-managers/svc/txn/ton/transfer")
    req.Storage = storage
    req.Data = map[string]interface{}{"name": "svc"}
    resp, err = b.HandleRequest(context.Background(), req)
    require.NoError(t, err)

    b64 := resp.Data["signed_boc"].(string)
    bocBytes, err := base64.StdEncoding.DecodeString(b64)
    require.NoError(t, err)
    require.NotEmpty(t, bocBytes)

    // Compute expected msg_id
    sum := sha256.Sum256(bocBytes)
    wantID := hex.EncodeToString(sum[:])
    gotID := resp.Data["msg_id"].(string)
    assert.Equal(t, wantID, gotID)
}

func TestTransferJetton(t *testing.T) {
    b, storage := newTestBackend(t)

    // Create manager
    req := logical.TestRequest(t, logical.UpdateOperation, "key-managers")
    req.Storage = storage
    req.Data = map[string]interface{}{"serviceName": "svc"}
    resp, err := b.HandleRequest(context.Background(), req)
    require.NoError(t, err)

    // Dummy Jetton transfer: returns seed as BOC
    req = logical.TestRequest(t, logical.CreateOperation, "key-managers/svc/txn/jetton/transfer")
    req.Storage = storage
    req.Data = map[string]interface{}{
        "name":         "svc",
        "jettonWallet": resp.Data["address"].(string),
    }
    resp, err = b.HandleRequest(context.Background(), req)
    require.NoError(t, err)

    b64 := resp.Data["signed_boc"].(string)
    bocBytes, err := base64.StdEncoding.DecodeString(b64)
    require.NoError(t, err)
    require.NotEmpty(t, bocBytes)

    sum := sha256.Sum256(bocBytes)
    wantID := hex.EncodeToString(sum[:])
    gotID := resp.Data["msg_id"].(string)
    assert.Equal(t, wantID, gotID)
}
