package ssh

import (
	"bytes"
	stdzlib "compress/zlib"
	"io"
	"testing"

	"golang.org/x/crypto/internal/sshzlib/zlib"
)

func TestZlibPacketReaderRoundTripWithStandardReader(t *testing.T) {
	chunks := [][]byte{
		[]byte("ssh "),
		[]byte("zlib@openssh.com "),
		bytes.Repeat([]byte("payload "), 128),
	}
	want := bytes.Join(chunks, nil)

	var compressed bytes.Buffer
	w := zlib.NewWriter(&compressed)
	var lastLen int
	var packets [][]byte
	for _, chunk := range chunks {
		if _, err := w.Write(chunk); err != nil {
			t.Fatal(err)
		}
		if err := w.PartialFlush(); err != nil {
			t.Fatal(err)
		}
		packets = append(packets, bytes.Clone(compressed.Bytes()[lastLen:]))
		lastLen = compressed.Len()
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	r, err := stdzlib.NewReader(bytes.NewReader(compressed.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("round trip mismatch")
	}

	packetReader := newZlibPacketReader()
	for i, packet := range packets {
		got, err := packetReader.ReadPacket(packet, 1<<20)
		if err != nil {
			t.Fatalf("ReadPacket(%d): %v", i, err)
		}
		if !bytes.Equal(got, chunks[i]) {
			t.Fatalf("ReadPacket(%d) = %q, want %q", i, got, chunks[i])
		}
	}
}
