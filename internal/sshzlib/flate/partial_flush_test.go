package flate

import (
	"bytes"
	stdflate "compress/flate"
	"io"
	"testing"
)

func TestPartialFlushRoundTrip(t *testing.T) {
	chunks := [][]byte{
		[]byte("hello, "),
		[]byte("world"),
		bytes.Repeat([]byte(" abcdefghijklmnopqrstuvwxyz"), 32),
		[]byte("tail"),
	}
	want := bytes.Join(chunks, nil)

	levels := []int{NoCompression, HuffmanOnly, BestSpeed, DefaultCompression, BestCompression}
	for _, level := range levels {
		var compressed bytes.Buffer
		w, err := NewWriter(&compressed, level)
		if err != nil {
			t.Fatalf("NewWriter(%d): %v", level, err)
		}

		var lastLen int
		for _, chunk := range chunks {
			if _, err := w.Write(chunk); err != nil {
				t.Fatalf("Write(%d): %v", level, err)
			}
			if err := w.PartialFlush(); err != nil {
				t.Fatalf("PartialFlush(%d): %v", level, err)
			}
			if compressed.Len() <= lastLen {
				t.Fatalf("PartialFlush(%d) did not emit bytes", level)
			}
			lastLen = compressed.Len()
		}
		if err := w.Close(); err != nil {
			t.Fatalf("Close(%d): %v", level, err)
		}

		r := stdflate.NewReader(bytes.NewReader(compressed.Bytes()))
		got, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("ReadAll(%d): %v", level, err)
		}
		if err := r.Close(); err != nil {
			t.Fatalf("reader Close(%d): %v", level, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("round trip mismatch at level %d", level)
		}

	}
}

func TestPartialFlushDoesNotEmitSyncFlushMarker(t *testing.T) {
	var compressed bytes.Buffer
	w, err := NewWriter(&compressed, DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.PartialFlush(); err != nil {
		t.Fatal(err)
	}

	got := compressed.Bytes()
	if bytes.HasSuffix(got, []byte{0x00, 0x00, 0xff, 0xff}) {
		t.Fatalf("PartialFlush emitted a sync-flush marker: % x", got)
	}
	if len(got) != 1 || got[0] != 0x02 {
		t.Fatalf("empty PartialFlush = % x, want 02", got)
	}
}
