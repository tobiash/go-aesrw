package aesrw

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestDecryptReader(t *testing.T) {
	masterKey, err := base64.StdEncoding.DecodeString("NATClAtbgGBJtJFz6dIku/hqoPL3GDCEokpXGZF6f7Q=")
	if err != nil {
		t.Fatal(err)
	}
	encFile, err := os.OpenFile(filepath.Join("testdata", "foo.pass.json.enc"), os.O_RDONLY, 0644)
	defer encFile.Close()
	cipher, err := aes.NewCipher(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	reader := NewCBCReader(encFile, cipher)
	res, err := ioutil.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := ioutil.ReadFile("testdata/foo.pass.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(expected) != string(res) {
		t.Errorf("Decryption had unexpected result:\n%s\nexpected:\n%s", string(res), string(expected))
	}
}

type testWriteCloser struct {
	io.Writer
}

func (w *testWriteCloser) Close() error {
	// Nothing
	return nil
}

type testReadCloser struct {
	io.Reader
}

func (w *testReadCloser) Close() error {
	return nil
}

func TestEncryptWriter(t *testing.T) {
	masterKey, err := base64.StdEncoding.DecodeString("NATClAtbgGBJtJFz6dIku/hqoPL3GDCEokpXGZF6f7Q=")
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := aes.NewCipher(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	buf := new(bytes.Buffer)
	backing := &testWriteCloser{buf}
	writer := NewCBCWriter(backing, cipher)
	writer.Write([]byte("Hello "))
	writer.Write([]byte("World12345"))
	writer.Close()

	// IV + plain text + 1 full block of padding since len(plaintext) == aes.BlockSize
	if buf.Len() != aes.BlockSize+len("Hello World12345")+aes.BlockSize {
		t.Errorf("Unexpected ciphertext length %d", buf.Len())
	}

	// fmt.Println(hex.Dump(buf.Bytes()))

	reader := NewCBCReader(&testReadCloser{buf}, cipher)
	res, err := ioutil.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(res) != "Hello World12345" {
		t.Error("Recovered plaintext did not match expectations")
	}
	// fmt.Println("Result:")
	// fmt.Println(string(res))
}
