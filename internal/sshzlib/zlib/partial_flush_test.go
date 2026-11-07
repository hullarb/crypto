package zlib

import (
	"bytes"
	stdzlib "compress/zlib"
	"io"
	"testing"
)

func TestPartialFlushRoundTripWithStandardReader(t *testing.T) {
	chunks := [][]byte{
		[]byte("ssh "),
		[]byte("zlib@openssh.com "),
		bytes.Repeat([]byte("payload "), 128),
	}
	want := bytes.Join(chunks, nil)

	var compressed bytes.Buffer
	w := NewWriter(&compressed)
	for _, chunk := range chunks {
		if _, err := w.Write(chunk); err != nil {
			t.Fatal(err)
		}
		if err := w.PartialFlush(); err != nil {
			t.Fatal(err)
		}
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

}
