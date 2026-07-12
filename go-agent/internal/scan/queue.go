package scan

import "sync"

type Queue struct {
	ch       chan FileItem
	done     chan struct{}
	once     sync.Once
	complete bool
	mu       sync.Mutex
}

func NewQueue(capacity int) *Queue {
	return &Queue{
		ch:   make(chan FileItem, capacity),
		done: make(chan struct{}),
	}
}

func (q *Queue) Enqueue(item FileItem) bool {
	q.mu.Lock()
	done := q.complete
	q.mu.Unlock()
	if done {
		return false
	}
	q.ch <- item
	return true
}

func (q *Queue) Complete() {
	q.once.Do(func() {
		q.mu.Lock()
		q.complete = true
		q.mu.Unlock()
		close(q.ch)
		close(q.done)
	})
}

func (q *Queue) DequeueBatch(max int) ([]FileItem, bool) {
	if max <= 0 {
		max = 1
	}
	batch := make([]FileItem, 0, max)
	for {
		select {
		case item, ok := <-q.ch:
			if !ok {
				if len(batch) == 0 {
					return nil, false
				}
				return batch, true
			}
			batch = append(batch, item)
			if len(batch) >= max {
				return batch, true
			}
		default:
			if len(batch) > 0 {
				return batch, true
			}
			q.mu.Lock()
			done := q.complete
			q.mu.Unlock()
			if done {
				item, ok := <-q.ch
				if !ok {
					return nil, false
				}
				return []FileItem{item}, true
			}
			item, ok := <-q.ch
			if !ok {
				return nil, false
			}
			batch = append(batch, item)
			if len(batch) >= max {
				return batch, true
			}
		}
	}
}
