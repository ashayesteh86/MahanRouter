package api

import (
	"bytes"
	"errors"
	"testing"
)

func TestBackupRoundTrip(t *testing.T) {
	plain := []byte("version: 1\nsystem:\n  hostname: r1\n")
	if IsEncryptedBackup(plain) {
		t.Fatal("plain YAML seen as encrypted")
	}
	if got, err := DecryptBackup(plain, ""); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("plain: %q %v", got, err)
	}
	enc, err := EncryptBackup(plain, "s3cret-pass")
	if err != nil {
		t.Fatal(err)
	}
	if !IsEncryptedBackup(enc) || bytes.Contains(enc, []byte("hostname")) {
		t.Fatalf("not encrypted: %s", enc)
	}
	if got, err := DecryptBackup(enc, "s3cret-pass"); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("decrypt: %q %v", got, err)
	}
	for _, pw := range []string{"", "wrong"} {
		if _, err := DecryptBackup(enc, pw); !errors.Is(err, ErrBackupPassword) {
			t.Fatalf("password %q: %v", pw, err)
		}
	}
	// a changed file must not decrypt
	bad := bytes.Replace(enc, []byte(`"data": "`), []byte(`"data": "AAAA`), 1)
	if _, err := DecryptBackup(bad, "s3cret-pass"); err == nil {
		t.Fatal("tampered backup accepted")
	}
}
