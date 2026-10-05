package main

import (
	"io"
	"log"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Write-behind
//
// The server handles a connection's requests one at a time, so a client's
// writes reach the proxy one after another, and writing each to the target
// before answering exposes a full round trip to the target per write: the
// macOS client writes 128 KiB at a time, which made writes through the proxy
// run at half the direct speed. Instead, a handle acknowledges a write once
// buffered, joins back-to-back writes into batches of up to writeBehindSize,
// and writes each batch to the target in the background while the client
// sends the next.
//
// A handle has at most one batch filling and one being written, so at most
// 2×writeBehindSize of acknowledged data is not on the target yet. A batch is
// sent when full, when a write does not continue it, after writeBehindIdle
// without writes, and before a request that could observe it: a read, open
// or security query on the same file, or any listing or change of file
// information, first waits out the pending writes (see syncWrites), so what
// a client reads, lists or queries through the proxy includes its writes. A failed
// background write is reported on the handle's next write, flush or close.
// ---------------------------------------------------------------------------

// writeBehindSize is the largest batch written to the target at once.
const writeBehindSize = readAheadSize

// writeBehindIdle is how long a partial batch waits for more writes; a
// variable so that tests can hold batches back.
var writeBehindIdle = 100 * time.Millisecond

// writeBehind is a handle's write-behind state; mu guards it.
type writeBehind struct {
	mu     sync.Mutex
	buf    []byte      // the batch filling, from getReadBuf; nil when none
	n      int         // bytes of buf filled
	off    int64       // file offset of buf[0]
	flight *batch      // the batch being written; nil when none
	err    error       // a failed background write, not yet reported
	timer  *time.Timer // sends a partial batch once writes pause
}

// batch is one background write; err is set before done is closed.
type batch struct {
	done chan struct{}
	err  error
}

// bufferWrite takes a write of data at off on ph for writing behind. It
// reports, instead, a background write that failed since the last report. A
// write larger than a batch is written through. The caller must hold
// ph.fileMu.RLock with ph.file non-nil.
func (v *proxyVFS) bufferWrite(ph *proxyHandle, off int64, data []byte) (int, error) {
	w := &ph.wb
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.err; err != nil {
		w.err = nil
		return 0, err
	}
	if w.buf != nil && (off != w.off+int64(w.n) || w.n+len(data) > len(w.buf)) {
		v.sendLocked(ph)
	}
	if len(data) > writeBehindSize {
		if err := v.waitLocked(ph); err != nil {
			w.err = nil
			return 0, err
		}
		v.up.mu.Lock()
		ctx, cancel := v.up.ioContext()
		n, err := ph.file.WriteFile(ctx, data, uint64(off))
		cancel()
		v.up.mu.Unlock()
		return n, err
	}
	if w.buf == nil {
		w.buf, w.n, w.off = getReadBuf(writeBehindSize), 0, off
		v.up.addPending(ph)
	}
	w.n += copy(w.buf[w.n:], data)
	switch {
	case w.n == len(w.buf):
		v.sendLocked(ph)
	case w.timer == nil:
		w.timer = time.AfterFunc(writeBehindIdle, func() { v.sendIdle(ph) })
	default:
		w.timer.Reset(writeBehindIdle)
	}
	return len(data), nil
}

// sendLocked starts writing the filling batch to the target, once the batch
// before it is written, so batches reach the target in order. The caller
// must hold ph.wb.mu and ph.fileMu (either way) with ph.file non-nil.
func (v *proxyVFS) sendLocked(ph *proxyHandle) {
	w := &ph.wb
	if w.buf == nil {
		return
	}
	v.collectLocked(ph)
	buf, n, off := w.buf, w.n, w.off
	w.buf, w.n = nil, 0
	b := &batch{done: make(chan struct{})}
	w.flight = b
	file := ph.file
	go func() {
		defer close(b.done)
		v.up.mu.Lock()
		ctx, cancel := v.up.ioContext()
		written, err := file.WriteFile(ctx, buf[:n], uint64(off))
		cancel()
		v.up.mu.Unlock()
		putReadBuf(buf)
		if err == nil && written < n {
			err = io.ErrShortWrite
		}
		b.err = err
	}()
}

// collectLocked waits for the batch being written, if any, and keeps its
// error for reporting. The caller must hold ph.wb.mu.
func (v *proxyVFS) collectLocked(ph *proxyHandle) {
	w := &ph.wb
	if w.flight == nil {
		return
	}
	<-w.flight.done
	if err := w.flight.err; err != nil {
		log.Printf("[proxy] write-behind to %q failed: %v", ph.Path(), err)
		if w.err == nil {
			w.err = err
		}
	}
	w.flight = nil
}

// waitLocked writes all of ph's pending data to the target and returns a
// failure not yet reported, which stays pending. The caller must hold
// ph.wb.mu and ph.fileMu (either way) with ph.file non-nil.
func (v *proxyVFS) waitLocked(ph *proxyHandle) error {
	w := &ph.wb
	v.sendLocked(ph)
	v.collectLocked(ph)
	if w.timer != nil {
		w.timer.Stop()
	}
	v.up.removePending(ph)
	return w.err
}

// sendIdle sends a partial batch once its handle's writes pause.
func (v *proxyVFS) sendIdle(ph *proxyHandle) {
	ph.fileMu.RLock()
	defer ph.fileMu.RUnlock()
	if ph.file == nil {
		return
	}
	ph.wb.mu.Lock()
	defer ph.wb.mu.Unlock()
	v.sendLocked(ph)
}

// flushWrites writes all of ph's pending data to the target and reports a
// failed background write, once. The caller must hold ph.fileMu (either
// way) with ph.file non-nil.
func (v *proxyVFS) flushWrites(ph *proxyHandle) error {
	ph.wb.mu.Lock()
	defer ph.wb.mu.Unlock()
	err := v.waitLocked(ph)
	ph.wb.err = nil
	return err
}

// syncWrites writes pending data on the connection to the target, before a
// request that could observe it: that of the handles open on path, or of
// every handle when path is empty. Failures stay pending for their own
// handles to report. The caller must not hold any handle's fileMu or wb.mu,
// nor the connection's mu.
func (v *proxyVFS) syncWrites(path string) {
	for _, ph := range v.up.pendingHandles() {
		if path != "" && !strings.EqualFold(ph.Path(), path) {
			continue
		}
		ph.fileMu.RLock()
		if ph.file != nil {
			ph.wb.mu.Lock()
			_ = v.waitLocked(ph)
			ph.wb.mu.Unlock()
		}
		ph.fileMu.RUnlock()
	}
}

// addPending notes that ph has data written behind on this connection.
func (u *upstream) addPending(ph *proxyHandle) {
	u.pendingMu.Lock()
	defer u.pendingMu.Unlock()
	if u.pending == nil {
		u.pending = make(map[*proxyHandle]struct{})
	}
	u.pending[ph] = struct{}{}
}

// removePending notes that ph's data is all on the target.
func (u *upstream) removePending(ph *proxyHandle) {
	u.pendingMu.Lock()
	defer u.pendingMu.Unlock()
	delete(u.pending, ph)
}

// pendingHandles returns the handles with data written behind.
func (u *upstream) pendingHandles() []*proxyHandle {
	u.pendingMu.Lock()
	defer u.pendingMu.Unlock()
	hs := make([]*proxyHandle, 0, len(u.pending))
	for ph := range u.pending {
		hs = append(hs, ph)
	}
	return hs
}
