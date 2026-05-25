package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"io"
	"os"

	"github.com/glebarez/sqlite"
	"github.com/gookit/slog"
	nestedset "github.com/longbridgeapp/nested-set"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// Category modella la gerarchia delle cartelle utilizzando il Nested Set Model
type Category struct {
	ID            int64         `gorm:"primaryKey;autoIncrement" nestedset:"id"`
	ParentID      sql.NullInt64 `nestedset:"parent_id"`
	Title         string
	Lft           int        `nestedset:"lft"`
	Rgt           int        `nestedset:"rgt"`
	Depth         int        `nestedset:"depth"`
	ChildrenCount int        `nestedset:"children_count"`
	Documents     []Document `gorm:"foreignKey:CategoryID"`
}

// Document modella il file archiviato
type Document struct {
	gorm.Model
	Title      string
	Content    string
	CategoryID int64
	Metadata   []Metadata `gorm:"foreignKey:DocumentID;constraint:OnDelete:CASCADE;"`
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
	if err := db.AutoMigrate(&Category{}, &Document{}, &Metadata{}); err != nil {
		slog.Fatalf("Errore nella migrazione automatica: %v", err)
	} else {
		slog.Info("Migrazione automatica completata con successo!")
	}

	// 3. Creazione Albero Cartelle
	root := Category{Title: "Archivio Centrale"}
	if err := nestedset.Create(db, &root, nil); err != nil {
		slog.Fatalf("Errore creazione nodo radice: %v", err)
	} else {
		slog.Info("Nodo radice creato con successo!")
	}

	itFolder := Category{Title: "Dipartimento IT"}
	if err := nestedset.Create(db, &itFolder, &root); err != nil {
		slog.Fatalf("Errore creazione nodo IT: %v", err)
	} else {
		slog.Info("Nodo IT creato con successo!")
	}

	manualsFolder := Category{Title: "Manuali Tecnici"}
	if err := nestedset.Create(db, &manualsFolder, &itFolder); err != nil {
		slog.Fatalf("Errore creazione nodo Manuali Tecnici: %v", err)
	} else {
		slog.Info("Nodo Manuali Tecnici creato con successo!")
	}

	// ==========================================
	// 4. PREPARAZIONE CONTENUTO E CALCOLO SHA256
	// ==========================================
	docContent := "Contenuto riservato del manuale di sicurezza..."
	fileHash := calculateSHA256(docContent)

	doc := Document{
		Title:      "Manuale Sicurezza Rete 2026",
		Content:    docContent,
		CategoryID: manualsFolder.ID,
		Metadata: []Metadata{
			{Key: "Autore", Value: "Mario Rossi"},
			{Key: "Versione", Value: "2.1"},
			// Aggiungiamo lo SHA256 calcolato dinamicamente
			{Key: "SHA256", Value: fileHash},
		},
	}

	// Salvataggio
	if err := db.Create(&doc).Error; err != nil {
		slog.Fatalf("Errore salvataggio documento: %v", err)
	}
	slog.Info("Documento e metadati (incluso SHA256) salvati")

	// ==========================================
	// 5. VERIFICA E STAMPA
	// ==========================================
	var fetchedDoc Document
	db.Preload("Metadata").First(&fetchedDoc, doc.ID)

	slog.Info("--- DETTAGLIO DOCUMENTO ---")
	slog.Info("Titolo documento", "titolo", fetchedDoc.Title)
	slog.Info("Metadati associati")
	for _, m := range fetchedDoc.Metadata {
		// Mettiamo in evidenza lo SHA256 nel logging strutturato
		if m.Key == "SHA256" {
			slog.Info("Metadato", "chiave", m.Key, "valore", m.Value, "valido", true)
		} else {
			slog.Info("Metadato", "chiave", m.Key, "valore", m.Value)
		}
	}
}
