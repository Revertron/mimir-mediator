package hybridcache

import (
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/dgraph-io/ristretto"
)

type HybridCache struct {
	mem *ristretto.Cache
	db  *badger.DB
}

func NewHybridCache(dbPath string, memSizeBytes int64) (*HybridCache, error) {
	opts := badger.DefaultOptions(dbPath)
	opts.Logger = nil
	opts.ValueLogFileSize = 256 << 20
	opts.BaseTableSize = 16 << 20
	db, err := badger.Open(opts)
	if err != nil {
		return nil, err
	}

	// ---- RAM ----
	mem, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: memSizeBytes / 64, // approximate
		MaxCost:     memSizeBytes,
		BufferItems: 64,
	})
	if err != nil {
		db.Close()
		return nil, err
	}

	hc := &HybridCache{mem: mem, db: db}
	go hc.runGC() // background cleanup for disk
	return hc, nil
}

func (h *HybridCache) Set(key string, val []byte, ttl time.Duration) error {
	// write to disk (durable)
	err := h.db.Update(func(txn *badger.Txn) error {
		e := badger.NewEntry([]byte(key), val).WithTTL(ttl)
		return txn.SetEntry(e)
	})
	if err != nil {
		return err
	}

	// cache in memory
	h.mem.SetWithTTL(key, val, int64(len(val)), 2*time.Minute)
	return nil
}

func (h *HybridCache) Get(key string) ([]byte, bool, error) {
	if v, ok := h.mem.Get(key); ok {
		return v.([]byte), true, nil
	}

	var valCopy []byte
	err := h.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}
		return item.Value(func(v []byte) error {
			valCopy = append([]byte(nil), v...)
			return nil
		})
	})
	if err != nil {
		if err == badger.ErrKeyNotFound {
			return nil, false, nil
		}
		return nil, false, err
	}

	// repopulate in RAM
	h.mem.SetWithTTL(key, valCopy, int64(len(valCopy)), 2*time.Minute)
	return valCopy, true, nil
}

func (h *HybridCache) runGC() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		for {
			err := h.db.RunValueLogGC(0.5)
			if err != nil {
				break
			}
		}
	}
}

func (h *HybridCache) Close() error {
	h.mem.Close()
	return h.db.Close()
}
