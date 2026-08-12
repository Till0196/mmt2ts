// Copyright 2026 Till0196
// SPDX-License-Identifier: Apache-2.0

// Package iopipe は標準入出力とファイルの安全な読み書きをまとめる。
package iopipe

import (
	"io"
	"sync"

	"mmt2ts/internal/iox"
)

type ReadAhead struct {
	ready chan block
	free  chan []byte
	cur   []byte
	curOw []byte
	err   error
	stop  chan struct{}
	once  sync.Once
}

type block struct {
	buf []byte
	own []byte
	err error
}

func NewReadAhead(r io.Reader, size, depth int) *ReadAhead {
	if size <= 0 {
		size = 1 << 20
	}
	if depth < 2 {
		depth = 2
	}
	a := &ReadAhead{
		ready: make(chan block, depth),
		free:  make(chan []byte, depth),
		stop:  make(chan struct{}),
	}
	for range depth {
		a.free <- make([]byte, size)
	}
	go a.fill(r)
	return a
}

func (a *ReadAhead) fill(r io.Reader) {
	defer close(a.ready)
	for {
		var buf []byte
		select {
		case buf = <-a.free:
		case <-a.stop:
			return
		}
		n, err := r.Read(buf)
		if n > 0 {
			select {
			case a.ready <- block{buf: buf[:n], own: buf}:
			case <-a.stop:
				return
			}
		}
		if err != nil {
			select {
			case a.ready <- block{err: err}:
			case <-a.stop:
			}
			return
		}
	}
}

func (a *ReadAhead) Read(p []byte) (int, error) {
	if len(a.cur) == 0 {
		if a.err != nil {
			return 0, a.err
		}
		b, ok := <-a.ready
		if !ok {
			a.err = io.EOF
			return 0, a.err
		}
		if b.err != nil {
			a.err = b.err
			return 0, a.err
		}
		a.cur, a.curOw = b.buf, b.own
	}
	n := copy(p, a.cur)
	a.cur = a.cur[n:]
	if len(a.cur) == 0 && a.curOw != nil {
		select {
		case a.free <- a.curOw:
		default:
		}
		a.curOw = nil
	}
	return n, nil
}

func (a *ReadAhead) Close() error {
	a.once.Do(func() { close(a.stop) })
	return nil
}

type ParallelReader struct {
	workers []*prWorker
	next    int
	cur     []byte
	curOwn  []byte
	owner   *prWorker
	err     error
	stop    chan struct{}
	once    sync.Once
}

type prWorker struct {
	ready chan block
	free  chan []byte
}

func NewParallelReader(ra io.ReaderAt, size int64, blockSize, workers, depth int) *ParallelReader {
	if blockSize <= 0 {
		blockSize = 1 << 20
	}
	if workers < 1 {
		workers = 1
	}
	if depth < 1 {
		depth = 1
	}
	p := &ParallelReader{stop: make(chan struct{})}
	for i := range workers {
		w := &prWorker{
			ready: make(chan block, depth),
			free:  make(chan []byte, depth+1),
		}
		for range depth + 1 {
			w.free <- make([]byte, blockSize)
		}
		p.workers = append(p.workers, w)
		go p.fetch(ra, w, int64(i)*int64(blockSize), int64(workers)*int64(blockSize), size)
	}
	return p
}

func (p *ParallelReader) fetch(ra io.ReaderAt, w *prWorker, off, stride, size int64) {
	defer close(w.ready)
	for ; size <= 0 || off < size; off += stride {
		var buf []byte
		select {
		case buf = <-w.free:
		case <-p.stop:
			return
		}
		n, err := ra.ReadAt(buf, off)
		if n > 0 {
			select {
			case w.ready <- block{buf: buf[:n], own: buf}:
			case <-p.stop:
				return
			}
		}
		if err != nil {
			select {
			case w.ready <- block{err: err}:
			case <-p.stop:
			}
			return
		}
	}
}

func (p *ParallelReader) Read(b []byte) (int, error) {
	if len(p.cur) == 0 {
		if p.err != nil {
			return 0, p.err
		}
		w := p.workers[p.next]
		p.next = (p.next + 1) % len(p.workers)
		blk, ok := <-w.ready
		if !ok {
			p.err = io.EOF
			return 0, p.err
		}
		if blk.err != nil {
			p.err = blk.err
			return 0, p.err
		}
		p.cur, p.curOwn, p.owner = blk.buf, blk.own, w
	}
	n := copy(b, p.cur)
	p.cur = p.cur[n:]
	if len(p.cur) == 0 && p.owner != nil {
		select {
		case p.owner.free <- p.curOwn:
		default:
		}
		p.curOwn, p.owner = nil, nil
	}
	return n, nil
}

func (p *ParallelReader) Close() error {
	p.once.Do(func() { close(p.stop) })
	return nil
}

type AsyncWriter struct {
	w     io.Writer
	size  int
	ready chan []byte
	free  chan []byte
	cur   []byte

	mu   sync.Mutex
	err  error
	done chan struct{}
	once sync.Once
}

func NewAsyncWriter(w io.Writer, size, depth int) *AsyncWriter {
	if size <= 0 {
		size = 1 << 20
	}
	if depth < 2 {
		depth = 2
	}
	a := &AsyncWriter{
		w:     w,
		size:  size,
		ready: make(chan []byte, depth),
		free:  make(chan []byte, depth),
		done:  make(chan struct{}),
	}
	for range depth {
		a.free <- make([]byte, 0, size)
	}
	go a.drain()
	return a
}

func (a *AsyncWriter) drain() {
	defer close(a.done)
	for buf := range a.ready {
		if a.failed() == nil {
			if err := iox.WriteFull(a.w, buf); err != nil {
				a.fail(err)
			}
		}
		select {
		case a.free <- buf[:0]:
		default:
		}
	}
}

func (a *AsyncWriter) failed() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.err
}

func (a *AsyncWriter) fail(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err == nil {
		a.err = err
	}
}

func (a *AsyncWriter) NextBlock() []byte {
	if a.cur == nil {
		a.cur = <-a.free
	}
	return a.cur[:0]
}

func (a *AsyncWriter) WriteBlock(b []byte) error {
	if err := a.failed(); err != nil {
		return err
	}
	a.cur = nil
	if len(b) == 0 {
		a.cur = b
		return nil
	}
	a.ready <- b
	return nil
}

func (a *AsyncWriter) Write(p []byte) (int, error) {
	if err := a.failed(); err != nil {
		return 0, err
	}
	written := 0
	for len(p) > 0 {
		if a.cur == nil {
			a.cur = <-a.free
		}
		n := copy(a.cur[len(a.cur):a.size], p)
		a.cur = a.cur[:len(a.cur)+n]
		p = p[n:]
		written += n
		if len(a.cur) == a.size {
			a.ready <- a.cur
			a.cur = nil
		}
	}
	return written, nil
}

func (a *AsyncWriter) Close() error {
	a.once.Do(func() {
		if len(a.cur) > 0 {
			a.ready <- a.cur
			a.cur = nil
		}
		close(a.ready)
		<-a.done
	})
	return a.failed()
}
