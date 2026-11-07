package ssh

import (
	"bytes"
	stdflate "compress/flate"
	"io"
	"testing"

	"golang.org/x/crypto/internal/sshzlib/flate"
)

func TestFlatePacketReaderRoundTrip(t *testing.T) {
	chunks := [][]byte{
		[]byte("hello, "),
		[]byte("world"),
		bytes.Repeat([]byte(" abcdefghijklmnopqrstuvwxyz"), 32),
		[]byte("tail"),
	}
	want := bytes.Join(chunks, nil)

	levels := []int{flate.NoCompression, flate.HuffmanOnly, flate.BestSpeed, flate.DefaultCompression, flate.BestCompression}
	for _, level := range levels {
		var compressed bytes.Buffer
		w, err := flate.NewWriter(&compressed, level)
		if err != nil {
			t.Fatalf("flate.NewWriter(%d): %v", level, err)
		}

		var lastLen int
		var packets [][]byte
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
			packets = append(packets, bytes.Clone(compressed.Bytes()[lastLen:]))
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

		packetReader := newFlatePacketReader()
		for i, packet := range packets {
			got, err := packetReader.ReadPacket(packet, 1<<20)
			if err != nil {
				t.Fatalf("ReadPacket(%d, %d): %v", level, i, err)
			}
			if !bytes.Equal(got, chunks[i]) {
				t.Fatalf("ReadPacket(%d, %d) = %q, want %q", level, i, got, chunks[i])
			}
		}
	}
}

func TestPacketReaderLimit(t *testing.T) {
	var compressed bytes.Buffer
	w, err := flate.NewWriter(&compressed, flate.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	if err := w.PartialFlush(); err != nil {
		t.Fatal(err)
	}

	_, err = newFlatePacketReader().ReadPacket(compressed.Bytes(), len("payload")-1)
	if err != errDecompressedSize {
		t.Fatalf("ReadPacket limit error = %v, want %v", err, errDecompressedSize)
	}
}
