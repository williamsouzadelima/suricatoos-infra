package tokens

import (
	"encoding/json"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

var bucketName = []byte("tokens")

// BoltStore is a BoltDB-backed persistent Store. It survives control-plane
// restarts and supports concurrent reads. Open it with NewBoltStore and close
// with Close when the process exits.
type BoltStore struct {
	db *bolt.DB
}

// NewBoltStore opens (or creates) a BoltDB database at path and ensures the
// token bucket exists. Returns an error if the file cannot be opened or locked.
func NewBoltStore(path string) (*BoltStore, error) {
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		return nil, fmt.Errorf("bolt.Open %s: %w", path, err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucketName)
		return err
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("criar bucket: %w", err)
	}
	return &BoltStore{db: db}, nil
}

// Close releases the BoltDB file lock. Must be called before process exit.
func (s *BoltStore) Close() error { return s.db.Close() }

// Put inserts or replaces a record.
func (s *BoltStore) Put(r Record) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		data, err := json.Marshal(r)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketName).Put([]byte(r.ID), data)
	})
}

// Get returns a copy of the record for the given id, or false if not found.
func (s *BoltStore) Get(id string) (Record, bool) {
	var r Record
	var found bool
	s.db.View(func(tx *bolt.Tx) error { //nolint:errcheck
		data := tx.Bucket(bucketName).Get([]byte(id))
		if data == nil {
			return nil
		}
		if err := json.Unmarshal(data, &r); err != nil {
			return err
		}
		found = true
		return nil
	})
	return r, found
}

// Update replaces an existing record; returns ErrNotFound if absent.
func (s *BoltStore) Update(r Record) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if b.Get([]byte(r.ID)) == nil {
			return ErrNotFound
		}
		data, err := json.Marshal(r)
		if err != nil {
			return err
		}
		return b.Put([]byte(r.ID), data)
	})
}

// List returns copies of all stored records in undefined order.
func (s *BoltStore) List() ([]Record, error) {
	var recs []Record
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketName).ForEach(func(_, v []byte) error {
			var r Record
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			recs = append(recs, r)
			return nil
		})
	})
	return recs, err
}
