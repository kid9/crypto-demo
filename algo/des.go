package algo

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"

	log "github.com/sirupsen/logrus"
)

// DES encrpyt: CBC mode
func DESEncrypt(plainText, iv, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		log.WithError(err).Error("failed to init des encrypt alog.")
		return nil, err
	}

	blockSize := block.BlockSize()
	// padding plaintext
	origData := PKCS5Padding(plainText, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, iv)
	cryted := make([]byte, len(origData))
	blockMode.CryptBlocks(cryted, origData)
	return cryted, nil
}

//DES decrypt: CBC mode
func DESDecrypt(cipherText, iv, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		log.WithError(err).Error("failed to init des decrypt alog.")
		return nil, err
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(cipherText))
	blockMode.CryptBlocks(origData, cipherText)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}

// DES encrypt: cfb mode
func DESCFBEncrypt(plainText, iv, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		log.WithError(err).Error("failed to init des encrypt(cfb)")
		return nil, err
	}
	blockSize := block.BlockSize()
	origData := PKCS5Padding(plainText, blockSize)
	blockMode := cipher.NewCFBEncrypter(block, iv)
	crypted := make([]byte, len(origData))
	blockMode.XORKeyStream(crypted, origData)
	return crypted, nil
}

func DESCFBDecrypt(cipherText, iv, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		log.WithError(err).Error("failed to init des descrypt(cfb)")
		return nil, err
	}
	blockMode := cipher.NewCFBDecrypter(block, iv)
	origData := make([]byte, len(cipherText))
	blockMode.XORKeyStream(origData, cipherText)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}

func PKCS5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func PKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}
