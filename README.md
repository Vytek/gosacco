![Go Sacco Logo](https://github.com/Vytek/gosacco/blob/main/logo_gosacco_mini.png?raw=true)

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/Vytek/gosacco)

# gosacco
Golang implementation secure system for Cloud (The name is a play on words related to Go for Golang and Sacco which in Italian identifies the sack, but also a tribute to General Luigi Sacco who was one of the pioneers of cryptography in Italy https://it.wikipedia.org/wiki/Luigi_Sacco)

## Motivation
This repo seeks to implement what was described in the course: https://www.decifris.it/attivita/trends25

## Interesting links
- https://github.com/fadeevab/cocoon (RUST)
- https://github.com/houz42/nested
  - https://github.com/longbridge/nested-set
  - https://github.com/safore-com/nested-set
- https://medium.com/@tsegstech10/detecting-file-changes-in-golang-with-checksums-efe31ec66f51
- https://github.com/glebarez/go-sqlite
- https://github.com/fentec-project/gofe
  - https://github.com/asvin-io/gofe-examples
  - [CP-ABE in Go](https://asecuritysite.com/golang/go_abe)
  - [CP-ABE using GPSW with String Attributes in Go](https://asecuritysite.com/golang/go_abe02)
  - [CP-ABE using GPSW in Go](https://asecuritysite.com/golang/go_abe03)
  - [CP-ABE using MAABE (Multi-authority (MA) attribute based encryption) in Go](https://asecuritysite.com/golang/go_abe04)
  - [CP-ABE with DIPPE (Decentralized Inner-Product Predicate Encryption) in Go](https://asecuritysite.com/golang/go_abe05)
  - [CP-ABE (Cipher Policy - Attributed-Based Encryption) with Kryptology](https://asecuritysite.com/golang/cp_abe)
- [CIRCL: Cloudflare Interoperable Reusable Cryptographic Library](https://github.com/cloudflare/circl)
  - [MLKEM](https://blog.moeghifar.com/post-quantum-key-encapsulation-ml-kem-performance-benchmark-between-go-library-and-cloudflare-006df9f759e1)
- [🐿️ A pure golang implementation of TFHE Fully Homomorphic Encryption Scheme](https://github.com/thedonutfactory/go-tfhe)
- [A library for lattice-based multiparty homomorphic encryption in Go](https://github.com/tuneinsight/lattigo)

## RPC API with rpcx

The application now starts an rpcx server and exposes remote APIs through the service `GoSacco`.

### Run

```bash
go run .
```

Environment variables:

- `RPCX_ADDR` (default: `0.0.0.0:8972`)
- `GOSACCO_DB_PATH` (default: `gosacco.db`)
- `CLOUD_MASTER_KEY_B64` (optional, base64 key of 32 bytes)

### Exposed methods

- `GoSacco.Health(*HealthArgs, *HealthReply)`
- `GoSacco.CreateCategory(*CreateCategoryArgs, *CreateCategoryReply)`
- `GoSacco.StoreDocument(*StoreDocumentArgs, *StoreDocumentReply)`
- `GoSacco.GetDocument(*GetDocumentArgs, *GetDocumentReply)`

### Example rpcx client

```go
package main

import (
  "context"
  "encoding/json"
  "fmt"

  "github.com/gookit/slog"
  "github.com/smallnest/rpcx/client"
)

type HealthArgs struct{}

type HealthReply struct {
  AppName  string
  Version  string
  Status   string
  UnixTime int64
}

type CreateCategoryArgs struct {
  Title    string
  ParentID int64
}

type CreateCategoryReply struct {
  CategoryID int64
}

type StoreDocumentArgs struct {
  Title      string
  CategoryID int64
  Content    string
  Metadata   map[string]string
}

type StoreDocumentReply struct {
  DocumentID   uint
  BlobID       uint
  ContentHash  string
  Deduplicated bool
}

type GetDocumentArgs struct {
  DocumentID uint
}

type GetDocumentReply struct {
  DocumentID  uint
  Title       string
  CategoryID  int64
  Content     string
  ContentHash string
  Metadata    map[string]string
}

func main() {
  d, err := client.NewPeer2PeerDiscovery("tcp@127.0.0.1:8972", "")
  if err != nil {
    panic(err)
  }
  xclient := client.NewXClient("GoSacco", client.Failtry, client.RandomSelect, d, client.DefaultOption)
  defer xclient.Close()

  req := &HealthArgs{}
  resp := &HealthReply{}
  if err := xclient.Call(context.Background(), "Health", req, resp); err != nil {
    panic(err)
  }
  fmt.Printf("%s %s status=%s\\n", resp.AppName, resp.Version, resp.Status)

  // Root category is created at startup and has ID 1 in a fresh database.
  createCatReq := &CreateCategoryArgs{Title: "Documenti Demo", ParentID: 1}
  createCatResp := &CreateCategoryReply{}
  if err := xclient.Call(context.Background(), "CreateCategory", createCatReq, createCatResp); err != nil {
    panic(err)
  }
  fmt.Printf("Created category id=%d\\n", createCatResp.CategoryID)

  storeReq := &StoreDocumentArgs{
    Title:      "nota.txt",
    CategoryID: createCatResp.CategoryID,
    Content:    "Contenuto riservato di esempio",
    Metadata: map[string]string{
      "owner": "alice",
      "scope": "demo",
    },
  }
  storeResp := &StoreDocumentReply{}
  if err := xclient.Call(context.Background(), "StoreDocument", storeReq, storeResp); err != nil {
    panic(err)
  }
  fmt.Printf("Stored document id=%d hash=%s dedup=%v\\n", storeResp.DocumentID, storeResp.ContentHash, storeResp.Deduplicated)

  getReq := &GetDocumentArgs{DocumentID: storeResp.DocumentID}
  getResp := &GetDocumentReply{}
  if err := xclient.Call(context.Background(), "GetDocument", getReq, getResp); err != nil {
    panic(err)
  }

  pretty, _ := json.MarshalIndent(getResp, "", "  ")
  slog.Infof("%s", string(pretty))
}
```
