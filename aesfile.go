package aesrw

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

var decryptionError = fmt.Errorf("decryption error")
var encryptionError = fmt.Errorf("encryption error")

// New creates a new AES encrypted file around a backing file
func NewCBCReader(backing io.ReadCloser, cipher cipher.Block) io.ReadCloser {
	return &aesreader{
		backing: backing,
		cipher:  cipher,
	}
}

func NewCBCWriter(backing io.WriteCloser, cipher cipher.Block) io.WriteCloser {
	return &aeswriter{
		backing: backing,
		cipher:  cipher,
	}
}

type aesreader struct {
	backing io.ReadCloser
	cipher  cipher.Block
	mode    cipher.BlockMode
	buffer  [aes.BlockSize]byte
	current []byte
	atEOF   bool
}

type aeswriter struct {
	backing io.WriteCloser
	cipher  cipher.Block
	mode    cipher.BlockMode
	buffer  [aes.BlockSize]byte
	b       int
}

func (r *aesreader) Read(p []byte) (n int, err error) {
	if r.mode == nil {
		// Read the IV first
		iv := r.buffer[:]
		if n, err := r.backing.Read(iv); n != len(iv) || err != nil {
			return 0, decryptionError
		}
		r.mode = cipher.NewCBCDecrypter(r.cipher, iv)
		r.current = r.buffer[:0]
	}
	for n < len(p) {
		if r.atEOF && len(r.current) == 0 {
			return n, io.EOF
		}
		if err != nil {
			return n, err
		}
		if len(r.current) == 0 && !r.atEOF {
			read, err := r.backing.Read(r.buffer[:])
			r.current = r.buffer[:read]
			if err == io.EOF {
				r.atEOF = true
			}
			r.mode.CryptBlocks(r.current, r.current)
			r.current, err = removePadding(r.current)
		}
		w := len(p) - n
		if len(r.current) < w {
			w = len(r.current)
		}
		copy(p[n:], r.current[:w])
		r.current = r.current[w:]
		n += w
	}
	return n, err
}

func (r *aeswriter) Write(p []byte) (n int, err error) {
	if r.mode == nil {
		if err = r.init(); err != nil {
			return 0, err
		}
	}
	for len(p)-n > 0 {
		// Write to buffer
		w := copy(r.buffer[r.b:], p[n:])
		r.b += w
		n += w
		if r.b == len(r.buffer) {
			// Drain buffer
			if _, err := r.drainBuffer(); err != nil {
				return n, err // TODO n?
			}
		}
	}
	return n, nil
}

func (r *aeswriter) init() error {
	iv := make([]byte, len(r.buffer))
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}
	if w, err := r.backing.Write(iv); w != len(iv) || err != nil {
		return encryptionError
	}
	r.mode = cipher.NewCBCEncrypter(r.cipher, iv)
	return nil
}

func (r *aeswriter) drainBuffer() (int, error) {
	data := r.buffer[:r.b]
	r.mode.CryptBlocks(data, data)
	r.b = 0
	return r.backing.Write(data)
}

func (r *aeswriter) Close() error {
	padLength := r.padCurrentBlock()
	if _, err := r.drainBuffer(); err != nil {
		return err
	}
	if padLength == 0 {
		// Need to write an additional padding block
		r.padCurrentBlock()
		if _, err := r.drainBuffer(); err != nil {
			return err
		}
	}
	return r.backing.Close()
}

func (r *aeswriter) padCurrentBlock() int {
	blockLength := r.b
	pad := len(r.buffer) - blockLength
	for i := r.b; i < len(r.buffer); i++ {
		r.buffer[i] = byte(pad)
	}
	r.b = len(r.buffer)
	return pad
}

func removePadding(block []byte) ([]byte, error) {
	if len(block) == 0 {
		return block, nil
	}
	padding := int(block[len(block)-1])
	if padding > len(block) {
		return block, decryptionError
	}
	return block[:len(block)-padding], nil
}

func (r *aesreader) Close() error {
	return r.backing.Close()
}
