package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/gookit/slog"
	nestedset "github.com/longbridgeapp/nested-set"
	siv "github.com/secure-io/siv-go"
	"github.com/smallnest/rpcx/server"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

const Version = "0.0.5"
const AppName = "GoSacco"

// Category modella la gerarchia delle cartelle utilizzando il Nested Set Model
type Category struct {
	ID               int64         `gorm:"primaryKey;autoIncrement" nestedset:"id"`
	ParentID         sql.NullInt64 `nestedset:"parent_id"`
	Title            string
	EncryptedNodeKey string
	Lft              int        `nestedset:"lft"`
	Rgt              int        `nestedset:"rgt"`
	Depth            int        `nestedset:"depth"`
	ChildrenCount    int        `nestedset:"children_count"`
	Documents        []Document `gorm:"foreignKey:CategoryID"`
}

// Blob rappresenta il contenuto cifrato deduplicato (una sola copia per hash contenuto)
type Blob struct {
	ID          uint   `gorm:"primaryKey;autoIncrement"`
	ContentHash string `gorm:"size:64;uniqueIndex"`
	Ciphertext  string `gorm:"type:text"`
}

// Document modella il file archiviato
type Document struct {
	gorm.Model
	Title            string
	BlobID           uint
	Blob             Blob `gorm:"constraint:OnDelete:RESTRICT;"`
	CategoryID       int64
	EncryptedFileKey string     `gorm:"type:text"`
	Metadata         []Metadata `gorm:"foreignKey:DocumentID;constraint:OnDelete:CASCADE;"`
}

// Metadata rappresenta le proprietà chiave-valore associate al documento
type Metadata struct {
	ID         uint `gorm:"primaryKey;autoIncrement"`
	DocumentID uint `gorm:"index"`
	Key        string
	Value      string
}

// Funzione di utilità per calcolare lo SHA256 di una stringa (o contenuto di un file)
func calculateSHA256(content string) string {
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:])
}

// Funzione di utilità per generare una chiave casuale di 32 byte (256 bit) per AES-256
func generateRandomKey32() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// Cifratura con nonce casuale: ogni cifratura produce un risultato diverso anche per lo stesso input.
func encryptRandomNonce(plaintext []byte, key []byte) (string, error) {
	gcmSIV, err := siv.NewGCM(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcmSIV.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcmSIV.Seal(nil, nonce, plaintext, nil)
	packed := append(nonce, ciphertext...)
	return base64.StdEncoding.EncodeToString(packed), nil
}

// Decifratura con nonce casuale: estrae il nonce dal pacchetto cifrato e lo usa per la decifratura.
func decryptRandomNonce(ciphertextB64 string, key []byte) ([]byte, error) {
	packed, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, err
	}
	gcmSIV, err := siv.NewGCM(key)
	if err != nil {
		return nil, err
	}
	nonceSize := gcmSIV.NonceSize()
	if len(packed) < nonceSize {
		return nil, errors.New("ciphertext non valido")
	}
	nonce, ciphertext := packed[:nonceSize], packed[nonceSize:]
	plaintext, err := gcmSIV.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// Cifratura convergente su AES-GCM-SIV: stessa chiave e stesso nonce deterministico per lo stesso contenuto.
func encryptConvergent(plaintext []byte, key []byte) (string, error) {
	gcmSIV, err := siv.NewGCM(key)
	if err != nil {
		return "", err
	}
	nonceSeed := sha256.Sum256(plaintext)
	nonce := nonceSeed[:gcmSIV.NonceSize()]
	ciphertext := gcmSIV.Seal(nil, nonce, plaintext, nil)
	packed := append([]byte{}, nonce...)
	packed = append(packed, ciphertext...)
	return base64.StdEncoding.EncodeToString(packed), nil
}

// Decifratura convergente: estrae il nonce deterministico dal pacchetto cifrato e lo usa per la decifratura.
func decryptConvergent(ciphertextB64 string, key []byte) ([]byte, error) {
	packed, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, err
	}
	gcmSIV, err := siv.NewGCM(key)
	if err != nil {
		return nil, err
	}
	nonceSize := gcmSIV.NonceSize()
	if len(packed) < nonceSize {
		return nil, errors.New("ciphertext convergente non valido")
	}
	nonce, ciphertext := packed[:nonceSize], packed[nonceSize:]
	plaintext, err := gcmSIV.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// Carica la chiave master cloud da variabile d'ambiente o genera una chiave volatile se non impostata.
func loadMasterCloudKey() ([]byte, error) {
	fromEnv := os.Getenv("CLOUD_MASTER_KEY_B64")
	if fromEnv == "" {
		key, err := generateRandomKey32()
		if err != nil {
			return nil, err
		}
		slog.Warn("CLOUD_MASTER_KEY_B64 non impostata: uso chiave master volatile per questa esecuzione")
		return key, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(fromEnv)
	if err != nil {
		return nil, err
	}
	if len(decoded) != 32 {
		return nil, errors.New("CLOUD_MASTER_KEY_B64 deve decodificare in 32 byte")
	}
	return decoded, nil
}

// Creazione di una categoria con generazione e cifratura della chiave nodo, e inserimento nel Nested Set.
func createCategoryWithNodeKey(db *gorm.DB, category *Category, parent *Category, parentKey []byte, masterKey []byte) ([]byte, error) {
	nodeKey, err := generateRandomKey32()
	if err != nil {
		return nil, err
	}
	if parent == nil {
		wrapped, err := encryptRandomNonce(nodeKey, masterKey)
		if err != nil {
			return nil, err
		}
		category.EncryptedNodeKey = wrapped
		if err := nestedset.Create(db, category, nil); err != nil {
			return nil, err
		}
		return nodeKey, nil
	}

	wrapped, err := encryptRandomNonce(nodeKey, parentKey)
	if err != nil {
		return nil, err
	}
	category.EncryptedNodeKey = wrapped
	if err := nestedset.Create(db, category, parent); err != nil {
		return nil, err
	}
	return nodeKey, nil
}

// Risoluzione ricorsiva della chiave nodo nel Nested Set.
func unwrapCategoryNodeKeyRecursive(db *gorm.DB, categoryID int64, masterKey []byte) ([]byte, error) {
	var c Category
	if err := db.First(&c, categoryID).Error; err != nil {
		return nil, err
	}
	if !c.ParentID.Valid {
		return decryptRandomNonce(c.EncryptedNodeKey, masterKey)
	}
	parentKey, err := unwrapCategoryNodeKeyRecursive(db, c.ParentID.Int64, masterKey)
	if err != nil {
		return nil, err
	}
	return decryptRandomNonce(c.EncryptedNodeKey, parentKey)
}

// Cifratura e decifratura dei metadati associati al documento usando la chiave nodo della categoria.
func encryptMetadataForNode(metadata []Metadata, nodeKey []byte) ([]Metadata, error) {
	encrypted := make([]Metadata, 0, len(metadata))
	for _, m := range metadata {
		encVal, err := encryptRandomNonce([]byte(m.Value), nodeKey)
		if err != nil {
			return nil, err
		}
		encrypted = append(encrypted, Metadata{Key: m.Key, Value: encVal})
	}
	return encrypted, nil
}

// Decifratura dei metadati associati al documento usando la chiave nodo della categoria.
func decryptMetadataForNode(metadata []Metadata, nodeKey []byte) ([]Metadata, error) {
	decrypted := make([]Metadata, 0, len(metadata))
	for _, m := range metadata {
		plainVal, err := decryptRandomNonce(m.Value, nodeKey)
		if err != nil {
			return nil, err
		}
		decrypted = append(decrypted, Metadata{Key: m.Key, Value: string(plainVal)})
	}
	return decrypted, nil
}

// Funzione di utilità per calcolare lo SHA256 di un file dato il suo percorso
func calculateFileSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

type GoSaccoService struct {
	db        *gorm.DB
	masterKey []byte
	mu        sync.Mutex
}

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

func (s *GoSaccoService) Health(_ context.Context, _ *HealthArgs, reply *HealthReply) error {
	*reply = HealthReply{
		AppName:  AppName,
		Version:  Version,
		Status:   "ok",
		UnixTime: time.Now().Unix(),
	}
	return nil
}

func (s *GoSaccoService) CreateCategory(_ context.Context, args *CreateCategoryArgs, reply *CreateCategoryReply) error {
	if args.Title == "" {
		return errors.New("title obbligatorio")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	category := Category{Title: args.Title}
	var parent *Category
	var parentKey []byte

	if args.ParentID > 0 {
		parent = &Category{}
		if err := s.db.First(parent, args.ParentID).Error; err != nil {
			return fmt.Errorf("parent category non trovata: %w", err)
		}

		key, err := unwrapCategoryNodeKeyRecursive(s.db, parent.ID, s.masterKey)
		if err != nil {
			return fmt.Errorf("impossibile risolvere la chiave nodo parent: %w", err)
		}
		parentKey = key
	}

	if _, err := createCategoryWithNodeKey(s.db, &category, parent, parentKey, s.masterKey); err != nil {
		return fmt.Errorf("creazione categoria fallita: %w", err)
	}

	reply.CategoryID = category.ID
	return nil
}

func (s *GoSaccoService) StoreDocument(_ context.Context, args *StoreDocumentArgs, reply *StoreDocumentReply) error {
	if args.Title == "" {
		return errors.New("title obbligatorio")
	}
	if args.CategoryID <= 0 {
		return errors.New("category_id non valido")
	}
	if args.Content == "" {
		return errors.New("content obbligatorio")
	}

	nodeKey, err := unwrapCategoryNodeKeyRecursive(s.db, args.CategoryID, s.masterKey)
	if err != nil {
		return fmt.Errorf("impossibile risolvere chiave categoria: %w", err)
	}

	fileHash := calculateSHA256(args.Content)
	fileKeyArr := sha256.Sum256([]byte(args.Content))
	fileKey := fileKeyArr[:]

	wrappedFileKey, err := encryptRandomNonce(fileKey, nodeKey)
	if err != nil {
		return fmt.Errorf("errore cifratura chiave file: %w", err)
	}

	contentCipher, err := encryptConvergent([]byte(args.Content), fileKey)
	if err != nil {
		return fmt.Errorf("errore cifratura contenuto: %w", err)
	}

	plainMetadata := make([]Metadata, 0, len(args.Metadata)+1)
	keys := make([]string, 0, len(args.Metadata))
	for k := range args.Metadata {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		plainMetadata = append(plainMetadata, Metadata{Key: k, Value: args.Metadata[k]})
	}
	plainMetadata = append(plainMetadata, Metadata{Key: "SHA256", Value: fileHash})

	encryptedMetadata, err := encryptMetadataForNode(plainMetadata, nodeKey)
	if err != nil {
		return fmt.Errorf("errore cifratura metadati: %w", err)
	}

	tx := s.db.Begin()
	if tx.Error != nil {
		return tx.Error
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	var blob Blob
	err = tx.Where("content_hash = ?", fileHash).First(&blob).Error
	deduplicated := false
	if errors.Is(err, gorm.ErrRecordNotFound) {
		blob = Blob{ContentHash: fileHash, Ciphertext: contentCipher}
		if err := tx.Create(&blob).Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("errore salvataggio blob: %w", err)
		}
	} else if err != nil {
		tx.Rollback()
		return fmt.Errorf("errore ricerca blob: %w", err)
	} else {
		deduplicated = true
	}

	doc := Document{
		Title:            args.Title,
		BlobID:           blob.ID,
		CategoryID:       args.CategoryID,
		EncryptedFileKey: wrappedFileKey,
		Metadata:         encryptedMetadata,
	}

	if err := tx.Create(&doc).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("errore salvataggio documento: %w", err)
	}

	if err := tx.Commit().Error; err != nil {
		return fmt.Errorf("errore commit transazione: %w", err)
	}

	reply.DocumentID = doc.ID
	reply.BlobID = blob.ID
	reply.ContentHash = fileHash
	reply.Deduplicated = deduplicated
	return nil
}

func (s *GoSaccoService) GetDocument(_ context.Context, args *GetDocumentArgs, reply *GetDocumentReply) error {
	var doc Document
	if err := s.db.Preload("Metadata").Preload("Blob").First(&doc, args.DocumentID).Error; err != nil {
		return fmt.Errorf("documento non trovato: %w", err)
	}

	nodeKey, err := unwrapCategoryNodeKeyRecursive(s.db, doc.CategoryID, s.masterKey)
	if err != nil {
		return fmt.Errorf("errore risoluzione chiave categoria: %w", err)
	}

	fileKey, err := decryptRandomNonce(doc.EncryptedFileKey, nodeKey)
	if err != nil {
		return fmt.Errorf("errore decifratura file key: %w", err)
	}

	contentPlain, err := decryptConvergent(doc.Blob.Ciphertext, fileKey)
	if err != nil {
		return fmt.Errorf("errore decifratura contenuto: %w", err)
	}

	metadataPlain, err := decryptMetadataForNode(doc.Metadata, nodeKey)
	if err != nil {
		return fmt.Errorf("errore decifratura metadati: %w", err)
	}

	metadataMap := make(map[string]string, len(metadataPlain))
	for _, m := range metadataPlain {
		metadataMap[m.Key] = m.Value
	}

	reply.DocumentID = doc.ID
	reply.Title = doc.Title
	reply.CategoryID = doc.CategoryID
	reply.Content = string(contentPlain)
	reply.ContentHash = doc.Blob.ContentHash
	reply.Metadata = metadataMap
	return nil
}

func ensureRootCategory(db *gorm.DB, masterKey []byte) (Category, error) {
	var root Category
	err := db.Where("parent_id IS NULL").Order("id asc").First(&root).Error
	if err == nil {
		return root, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return Category{}, err
	}

	root = Category{Title: "Archivio Centrale"}
	if _, err := createCategoryWithNodeKey(db, &root, nil, nil, masterKey); err != nil {
		return Category{}, err
	}
	return root, nil
}

// Funzione principale
func main() {
	masterKey, err := loadMasterCloudKey()
	if err != nil {
		slog.Fatalf("Errore caricamento chiave master cloud: %v", err)
	}

	dbPath := os.Getenv("GOSACCO_DB_PATH")
	if dbPath == "" {
		dbPath = "gosacco.db"
	}

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		slog.Fatalf("Errore connessione DB: %v", err)
	}

	if err := db.AutoMigrate(&Category{}, &Blob{}, &Document{}, &Metadata{}); err != nil {
		slog.Fatalf("Errore migrazione DB: %v", err)
	}

	root, err := ensureRootCategory(db, masterKey)
	if err != nil {
		slog.Fatalf("Errore inizializzazione categoria root: %v", err)
	}
	slog.Info("Categoria root pronta", "id", root.ID, "title", root.Title)

	rpcService := &GoSaccoService{db: db, masterKey: masterKey}
	rpcServer := server.NewServer()
	if err := rpcServer.RegisterName("GoSacco", rpcService, ""); err != nil {
		slog.Fatalf("Errore registrazione servizio rpcx: %v", err)
	}

	addr := os.Getenv("RPCX_ADDR")
	if addr == "" {
		addr = "0.0.0.0:8972"
	}

	slog.Info("Server rpcx avviato", "service", "GoSacco", "addr", addr)
	if err := rpcServer.Serve("tcp", addr); err != nil {
		slog.Fatalf("Errore avvio server rpcx: %v", err)
	}
}
