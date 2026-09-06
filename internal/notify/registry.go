package notify

import (
	"sort"
	"sync"
)

type Registry[T any] struct {
	mu    sync.RWMutex
	items map[string]T
}

func NewRegistry[T any]() *Registry[T] {
	return &Registry[T]{items: make(map[string]T)}
}

func (r *Registry[T]) Register(key string, item T) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.items[key] = item
}

func (r *Registry[T]) Get(key string) (T, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	v, ok := r.items[key]
	return v, ok
}

func (r *Registry[T]) Keys() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	keys := make([]string, 0, len(r.items))
	for k := range r.items {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (r *Registry[T]) All() []T {
	r.mu.RLock()
	defer r.mu.RUnlock()
	keys := make([]string, 0, len(r.items))
	for k := range r.items {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]T, 0, len(keys))
	for _, k := range keys {
		out = append(out, r.items[k])
	}
	return out
}
