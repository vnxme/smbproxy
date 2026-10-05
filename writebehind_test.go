package main

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/smb"
)

// snapshot returns a copy of ff's data and its WriteFile count.
func (f *fakeFile) snapshot() ([]byte, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]byte(nil), f.data...), f.writes
}

// Back-to-back writes are joined into batches of writeBehindSize, written to
// the target by the time a flush returns.
func TestWriteBehindJoinsWrites(t *testing.T) {
	// No batch is sent for want of writes, however slowly this test runs.
	idle := writeBehindIdle
	writeBehindIdle = time.Hour
	t.Cleanup(func() { writeBehindIdle = idle })

	ff := &fakeFile{}
	v := newVFS(&fakeConn{})
	ph := fileHandle(ff)
	ctx := context.Background()

	want := make([]byte, 2*writeBehindSize+300<<10)
	for i := range want {
		want[i] = byte(i / 5)
	}
	const chunk = 128 << 10
	for off := 0; off < len(want); off += chunk {
		end := min(off+chunk, len(want))
		if n, status, _ := v.Write(ctx, ph, int64(off), want[off:end]); status != smb.StatusOk || n != end-off {
			t.Fatalf("Write at %d = (%d, 0x%08x), want (%d, Ok)", off, n, status, end-off)
		}
	}
	if status, _ := v.Flush(ctx, ph); status != smb.StatusOk {
		t.Fatalf("Flush = 0x%08x, want Ok", status)
	}
	got, writes := ff.snapshot()
	if !bytes.Equal(got, want) {
		t.Errorf("target data differs from what was written (%d bytes, want %d)", len(got), len(want))
	}
	if writes != 3 {
		t.Errorf("upstream WriteFile called %d times, want 3: two full batches and the rest", writes)
	}
}

// Writes that do not continue the batch, overlapping or going back, reach
// the target in the order they were made.
func TestWriteBehindKeepsOrder(t *testing.T) {
	ff := &fakeFile{data: []byte("..........")}
	v := newVFS(&fakeConn{})
	ph := fileHandle(ff)
	ctx := context.Background()

	for _, w := range []struct {
		off  int64
		data string
	}{{0, "aaaa"}, {6, "bbbb"}, {2, "cc"}, {3, "D"}, {9, "EE"}} {
		if _, status, _ := v.Write(ctx, ph, w.off, []byte(w.data)); status != smb.StatusOk {
			t.Fatalf("Write %q at %d = 0x%08x, want Ok", w.data, w.off, status)
		}
	}
	if err := v.Close(ctx, ph); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got, _ := ff.snapshot(); string(got) != "aacD..bbbEE" {
		t.Errorf("target data %q, want aacD..bbbEE", got)
	}
}

// A partial batch is written to the target once writes pause, without a
// flush.
func TestWriteBehindIdle(t *testing.T) {
	ff := &fakeFile{}
	v := newVFS(&fakeConn{})
	ph := fileHandle(ff)

	if _, status, _ := v.Write(context.Background(), ph, 0, []byte("idle")); status != smb.StatusOk {
		t.Fatalf("Write = 0x%08x, want Ok", status)
	}
	deadline := time.Now().Add(20 * writeBehindIdle)
	for {
		if got, _ := ff.snapshot(); string(got) == "idle" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("pending write not on the target after the writes paused")
		}
		time.Sleep(writeBehindIdle / 4)
	}
	if err := v.Close(context.Background(), ph); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// A request on the same file through another handle, or a listing, sees the
// writes still pending on a handle.
func TestWriteBehindVisibleToOthers(t *testing.T) {
	ff := &fakeFile{data: []byte("0000")}
	v := newVFS(&fakeConn{})
	writer := fileHandle(ff)
	writer.path = `\f.txt`
	reader := fileHandle(ff)
	reader.path = `\F.TXT` // paths compare as the client's do, without case
	ctx := context.Background()

	if _, status, _ := v.Write(ctx, writer, 0, []byte("1234")); status != smb.StatusOk {
		t.Fatalf("Write = 0x%08x, want Ok", status)
	}
	buf := make([]byte, 4)
	if n, status, _ := v.Read(ctx, reader, 0, buf); status != smb.StatusOk || string(buf[:n]) != "1234" {
		t.Errorf("read through another handle = (%q, 0x%08x), want 1234", buf[:n], status)
	}
	drainPrefetch(reader)

	if _, status, _ := v.Write(ctx, writer, 0, []byte("5")); status != smb.StatusOk {
		t.Fatalf("Write = 0x%08x, want Ok", status)
	}
	v.syncWrites("") // as a listing or a change of file information does
	if got, _ := ff.snapshot(); string(got) != "5234" {
		t.Errorf("target data after a sync %q, want 5234", got)
	}
	for _, h := range []*proxyHandle{writer, reader} {
		if err := v.Close(ctx, h); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}
}

// A background write that fails is reported once, on the next write, and the
// data written after it is still taken.
func TestWriteBehindReportsFailure(t *testing.T) {
	ff := &fakeFile{}
	v := newVFS(&fakeConn{})
	ph := fileHandle(ff)
	ctx := context.Background()

	ff.mu.Lock()
	ff.writeErr = smb.StatusMap[smb.StatusAccessDenied]
	ff.mu.Unlock()
	if _, status, _ := v.Write(ctx, ph, 0, []byte("lost")); status != smb.StatusOk {
		t.Fatalf("Write = 0x%08x, want Ok", status)
	}
	v.syncWrites("")
	ff.mu.Lock()
	ff.writeErr = nil
	ff.mu.Unlock()

	if _, status, _ := v.Write(ctx, ph, 0, []byte("next")); status != smb.StatusAccessDenied {
		t.Errorf("write after a failed one = 0x%08x, want STATUS_ACCESS_DENIED", status)
	}
	if n, status, _ := v.Write(ctx, ph, 0, []byte("next")); status != smb.StatusOk || n != 4 {
		t.Errorf("write after the report = (%d, 0x%08x), want (4, Ok)", n, status)
	}
	if status, _ := v.Flush(ctx, ph); status != smb.StatusOk {
		t.Errorf("Flush = 0x%08x, want Ok", status)
	}
	if got, _ := ff.snapshot(); string(got) != "next" {
		t.Errorf("target data %q, want next", got)
	}
}

// Writes larger than a batch are written through, after the pending ones.
func TestWriteBehindLargeWrite(t *testing.T) {
	ff := &fakeFile{}
	v := newVFS(&fakeConn{})
	ph := fileHandle(ff)
	ctx := context.Background()

	big := bytes.Repeat([]byte("b"), writeBehindSize+1)
	if _, status, _ := v.Write(ctx, ph, 0, []byte("aaaa")); status != smb.StatusOk {
		t.Fatalf("Write = 0x%08x, want Ok", status)
	}
	if n, status, _ := v.Write(ctx, ph, 2, big); status != smb.StatusOk || n != len(big) {
		t.Fatalf("large Write = (%d, 0x%08x), want (%d, Ok)", n, status, len(big))
	}
	got, _ := ff.snapshot()
	if want := append([]byte("aa"), big...); !bytes.Equal(got, want) {
		t.Errorf("target data after a large write differs (%d bytes, want %d)", len(got), len(want))
	}
	if err := v.Close(ctx, ph); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// Handles written, read, flushed and closed from several goroutines at once
// each end up with exactly what was written to them.
func TestWriteBehindConcurrent(t *testing.T) {
	v := newVFS(&fakeConn{})
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for g := range 4 {
		wg.Go(func() {
			ff := &fakeFile{}
			ph := fileHandle(ff)
			want := make([]byte, 3*writeBehindSize/2)
			for i := range want {
				want[i] = byte(g*31 + i/3)
			}
			buf := make([]byte, 1000)
			for off := 0; off < len(want); off += 64 << 10 {
				end := min(off+64<<10, len(want))
				if _, status, _ := v.Write(ctx, ph, int64(off), want[off:end]); status != smb.StatusOk {
					errs <- errors.New("write failed")
					return
				}
				if off%(1<<20) == 0 {
					n, _, _ := v.Read(ctx, ph, int64(off), buf)
					if !bytes.Equal(buf[:n], want[off:off+n]) {
						errs <- errors.New("read back differs")
						return
					}
				}
			}
			if err := v.Close(ctx, ph); err != nil {
				errs <- err
				return
			}
			if got, _ := ff.snapshot(); !bytes.Equal(got, want) {
				errs <- errors.New("target data differs")
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
