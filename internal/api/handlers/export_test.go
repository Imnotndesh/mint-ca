package handlers

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"testing"
)

func TestTarGz_RoundTrip(t *testing.T) {
	data, err := tarGz(map[string][]byte{
		"a.txt":  []byte("hello\n"),
		"b.json": []byte(`{"x":1}`),
	})
	if err != nil {
		t.Fatalf("tarGz: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("empty archive")
	}

	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	found := map[string]string{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		b, _ := io.ReadAll(tr)
		found[hdr.Name] = string(b)
	}
	if found["a.txt"] != "hello\n" {
		t.Errorf("a.txt = %q", found["a.txt"])
	}
	if found["b.json"] != `{"x":1}` {
		t.Errorf("b.json = %q", found["b.json"])
	}
}
