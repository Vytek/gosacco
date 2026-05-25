package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"

	"github.com/glebarez/sqlite"
	"github.com/gookit/slog"
	nestedset "github.com/longbridgeapp/nested-set"
	siv "github.com/secure-io/siv-go"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

const Version = "0.0.4"
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

// Funzione principale
func main() {
	// 0. Caricamento chiave master cloud
	masterKey, err := loadMasterCloudKey()
	if err != nil {
		slog.Fatalf("Errore caricamento chiave master cloud: %v", err)
	}

	// 1. Connessione al DB in memoria
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		// Nested-set interroga la tabella vuota al primo avvio: evitiamo il log "record not found" atteso.
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		slog.Fatalf("Errore nella connessione al DB: %v", err)
	} else {
		slog.Info("Connessione al DB avvenuta con successo!")
	}

	// 2. Auto-Migrazione
	if err := db.AutoMigrate(&Category{}, &Blob{}, &Document{}, &Metadata{}); err != nil {
		slog.Fatalf("Errore nella migrazione automatica: %v", err)
	} else {
		slog.Info("Migrazione automatica completata con successo!")
	}

	// 3. Creazione Albero Cartelle
	root := Category{Title: "Archivio Centrale"}
	rootKey, err := createCategoryWithNodeKey(db, &root, nil, nil, masterKey)
	if err != nil {
		slog.Fatalf("Errore creazione nodo radice: %v", err)
	} else {
		slog.Info("Nodo radice creato con successo!")
	}

	itFolder := Category{Title: "Dipartimento IT"}
	itKey, err := createCategoryWithNodeKey(db, &itFolder, &root, rootKey, masterKey)
	if err != nil {
		slog.Fatalf("Errore creazione nodo IT: %v", err)
	} else {
		slog.Info("Nodo IT creato con successo!")
	}

	manualsFolder := Category{Title: "Manuali Tecnici"}
	_, err = createCategoryWithNodeKey(db, &manualsFolder, &itFolder, itKey, masterKey)
	if err != nil {
		slog.Fatalf("Errore creazione nodo Manuali Tecnici: %v", err)
	} else {
		slog.Info("Nodo Manuali Tecnici creato con successo!")
	}

	// ==========================================
	// 4. PREPARAZIONE CONTENUTO E CALCOLO SHA256
	// ==========================================
	docContent := "Contenuto riservato del manuale di sicurezza..."
	// fileHash è lo SHA256 del contenuto, usato per la deduplica a livello di blob.
	fileHash := calculateSHA256(docContent)
	// filekeyArr è la chiave simmetrica derivata dallo SHA256 del contenuto, usata per la cifratura convergente e per la deduplica.
	fileKeyArr := sha256.Sum256([]byte(docContent))
	// fileKey è la chiave simmetrica di 32 byte usata per cifrare il contenuto e che sarà cifrata con la chiave nodo.
	fileKey := fileKeyArr[:]

	// nodeKey è la chiave nodo della categoria "Manuali Tecnici", ottenuta risolvendo ricorsivamente la catena di cifrature dal nodo radice.
	nodeKey, err := unwrapCategoryNodeKeyRecursive(db, manualsFolder.ID, masterKey)
	if err != nil {
		slog.Fatalf("Errore risoluzione ricorsiva chiave nodo: %v", err)
	}

	// wrappedFileKey è la chiave simmetrica del file cifrata con la chiave nodo della categoria, da salvare nel documento.
	wrappedFileKey, err := encryptRandomNonce(fileKey, nodeKey)
	if err != nil {
		slog.Fatalf("Errore cifratura chiave file con chiave nodo: %v", err)
	}

	// contentCipher è il contenuto cifrato con cifratura convergente, da salvare nel blob.
	contentCipher, err := encryptConvergent([]byte(docContent), fileKey)
	if err != nil {
		slog.Fatalf("Errore cifratura convergente contenuto: %v", err)
	}

	// Controllo deduplica: cerco un blob con lo stesso hash del contenuto. Se non esiste, lo creo. Altrimenti, riuso il blob esistente.
	var blob Blob
	err = db.Where("content_hash = ?", fileHash).First(&blob).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		blob = Blob{ContentHash: fileHash, Ciphertext: contentCipher}
		if err := db.Create(&blob).Error; err != nil {
			slog.Fatalf("Errore salvataggio blob deduplicato: %v", err)
		}
		slog.Info("Nuovo blob cifrato salvato", "hash", fileHash)
	} else if err != nil {
		slog.Fatalf("Errore ricerca blob deduplicato: %v", err)
	} else {
		slog.Info("Deduplica attiva: riuso blob esistente", "hash", fileHash, "blob_id", blob.ID)
	}

	// Cifratura dei metadati (incluso lo SHA256) con la chiave nodo della categoria.
	plainMetadata := []Metadata{
		{Key: "Autore", Value: "Mario Rossi"},
		{Key: "Versione", Value: "2.1"},
		{Key: "SHA256", Value: fileHash},
	}
	// encryptedMetadata è la versione cifrata dei metadati, da salvare nel documento.
	encryptedMetadata, err := encryptMetadataForNode(plainMetadata, nodeKey)
	if err != nil {
		slog.Fatalf("Errore cifratura metadati con chiave nodo: %v", err)
	}

	doc := Document{
		Title:            "Manuale Sicurezza Rete 2026",
		BlobID:           blob.ID,
		CategoryID:       manualsFolder.ID,
		EncryptedFileKey: wrappedFileKey,
		Metadata:         encryptedMetadata,
	}

	// Salvataggio
	if err := db.Create(&doc).Error; err != nil {
		slog.Fatalf("Errore salvataggio documento: %v", err)
	}
	slog.Info("Documento e metadati (incluso SHA256) salvati")

	// Dimostrazione deduplica: stesso contenuto, nuovo documento, stesso blob.
	doc2 := Document{
		Title:            "Copia Manuale Sicurezza Rete 2026",
		BlobID:           blob.ID,
		CategoryID:       manualsFolder.ID,
		EncryptedFileKey: wrappedFileKey,
		Metadata:         encryptedMetadata,
	}
	if err := db.Create(&doc2).Error; err != nil {
		slog.Fatalf("Errore salvataggio secondo documento deduplicato: %v", err)
	}
	slog.Info("Secondo documento salvato senza duplicare il blob", "blob_id", blob.ID)

	// ==========================================
	// 5. VERIFICA E STAMPA
	// ==========================================
	var fetchedDoc Document
	if err := db.Preload("Metadata").Preload("Blob").First(&fetchedDoc, doc.ID).Error; err != nil {
		slog.Fatalf("Errore fetch documento: %v", err)
	}

	nodeKeyForRead, err := unwrapCategoryNodeKeyRecursive(db, fetchedDoc.CategoryID, masterKey)
	if err != nil {
		slog.Fatalf("Errore risoluzione chiave nodo in lettura: %v", err)
	}

	unwrappedFileKey, err := decryptRandomNonce(fetchedDoc.EncryptedFileKey, nodeKeyForRead)
	if err != nil {
		slog.Fatalf("Errore decifratura chiave file: %v", err)
	}

	decryptedContent, err := decryptConvergent(fetchedDoc.Blob.Ciphertext, unwrappedFileKey)
	if err != nil {
		slog.Fatalf("Errore decifratura contenuto blob: %v", err)
	}

	decryptedMetadata, err := decryptMetadataForNode(fetchedDoc.Metadata, nodeKeyForRead)
	if err != nil {
		slog.Fatalf("Errore decifratura metadati: %v", err)
	}

	slog.Info("--- DETTAGLIO DOCUMENTO ---")
	slog.Info("Titolo documento", "titolo", fetchedDoc.Title)
	slog.Info("Blob associato", "blob_id", fetchedDoc.BlobID, "content_hash", fetchedDoc.Blob.ContentHash)
	slog.Info("Contenuto decifrato", "contenuto", string(decryptedContent))
	slog.Info("Metadati associati")
	for _, m := range decryptedMetadata {
		// Mettiamo in evidenza lo SHA256 nel logging strutturato
		if m.Key == "SHA256" {
			slog.Info("Metadato", "chiave", m.Key, "valore", m.Value, "valido", true)
		} else {
			slog.Info("Metadato", "chiave", m.Key, "valore", m.Value)
		}
	}
}
