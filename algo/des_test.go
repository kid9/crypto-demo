package algo_test

import (
	"testing"

	"github.com/kid9/crypto-demo/algo"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

var (
	IV  = []byte("initvect")
	key = []byte("secretke")
)

func TestDesEncryptionAndDecryption(t *testing.T) {
	plainText := []byte("this is a plaintext.")
	cipherText, err := algo.DESEncrypt(plainText, IV, key)
	if err != nil {
		t.Errorf("encrypt text failed: %s", err.Error())
		return
	}
	log.Infof("cipher text: %s", string(cipherText))

	decodedText, err := algo.DESDecrypt(cipherText, IV, key)
	if err != nil {
		t.Errorf("decrypt text failed: %s", err.Error())
		return
	}
	log.Infof("decoded text: %s", string(decodedText))
	assert.EqualValues(t, plainText, decodedText)
}

func TestDesCfbEncryptionAndDecryption(t *testing.T) {
	plainText := []byte("this is a plaintext.")
	cipherText, err := algo.DESCFBEncrypt(plainText, IV, key)
	if err != nil {
		t.Errorf("encrypt text(cfb) failed: %s", err.Error())
		return
	}
	log.Infof("cipher text(cfb): %s", string(cipherText))

	decodedText, err := algo.DESCFBDecrypt(cipherText, IV, key)
	if err != nil {
		t.Errorf("decrypt text(cfb) failed: %s", err.Error())
		return
	}
	log.Infof("decoded text(cfb): %s", string(decodedText))
	assert.EqualValues(t, plainText, decodedText)
}
