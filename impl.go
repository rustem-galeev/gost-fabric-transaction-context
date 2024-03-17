package gost_fabric_transaction_context

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"github.com/rustem-galeev/gost-crypto-algs/encrypt128"
	"github.com/rustem-galeev/gost-crypto-algs/encrypt64"
)

type BlockEncryptionAlg int

type BlockEncryptionModeAlg int

const (
	BlockEncryption64Alg = iota
	BlockEncryption128Alg
)

type gostTransactionContextImpl struct {
	contractapi.TransactionContext

	iv                 []byte
	blockEncryptionAlg BlockEncryptionAlg
}

func Init(blockEncryptionAlg BlockEncryptionAlg) (GostTransactionContextInterface, error) {
	return &gostTransactionContextImpl{
			blockEncryptionAlg: blockEncryptionAlg,
		},
		nil
}

func (ctx *gostTransactionContextImpl) PutState(key string, value, cipherKey []byte) error {
	encryptedValue, err := ctx.encrypt(value, cipherKey)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(key, encryptedValue)
}

func (ctx *gostTransactionContextImpl) GetState(key string, decryptKey []byte) ([]byte, error) {
	encryptedValue, err := ctx.GetStub().GetState(key)
	if err != nil {
		return nil, err
	}

	value, err := ctx.decrypt(encryptedValue, decryptKey)
	if err != nil {
		return nil, err
	}

	return value, nil
}

func (ctx *gostTransactionContextImpl) encrypt(plainData, key []byte) ([]byte, error) {
	if plainData == nil {
		return nil, fmt.Errorf("data for encryption wasn't provided")
	}

	encryptor, err := ctx.getEncryptor(key)
	if err != nil {
		return nil, fmt.Errorf("error during creating encryptor.\n %w", err)
	}

	var dst = make([]byte, 0)
	encryptor.CryptBlocks(dst, plainData)
	return dst, nil
}

func (ctx *gostTransactionContextImpl) decrypt(cipherData, key []byte) ([]byte, error) {
	if cipherData == nil {
		return nil, fmt.Errorf("data for decryption wasn't provided")
	}

	encryptor, err := ctx.getDecrypter(key)
	if err != nil {
		return nil, fmt.Errorf("error during creating decrypter.\n %w", err)
	}

	var dst = make([]byte, 0)
	encryptor.CryptBlocks(dst, cipherData)
	return dst, nil
}

func (ctx *gostTransactionContextImpl) getEncryptor(key []byte) (cipher.BlockMode, error) {
	block, err := ctx.getBlock(key)
	if err != nil {
		return nil, err
	}
	if ctx.iv == nil {
		ctx.iv = make([]byte, block.BlockSize())
		_, err := rand.Read(ctx.iv)
		if err != nil {
			return nil, err
		}
	}

	return cipher.NewCBCEncrypter(block, ctx.iv), nil
}

func (ctx *gostTransactionContextImpl) getDecrypter(key []byte) (cipher.BlockMode, error) {
	block, err := ctx.getBlock(key)
	if err != nil {
		return nil, err
	}

	if ctx.iv == nil {
		ctx.iv = make([]byte, block.BlockSize())
		_, err := rand.Read(ctx.iv)
		if err != nil {
			return nil, err
		}
	}

	return cipher.NewCBCDecrypter(block, ctx.iv), nil
}

func (ctx *gostTransactionContextImpl) getBlock(key []byte) (cipher.Block, error) {
	switch ctx.blockEncryptionAlg {
	case BlockEncryption64Alg:
		return encrypt64.New(key)
	case BlockEncryption128Alg:
		return encrypt128.New(key)
	default:
		return nil, fmt.Errorf("Unknown block encryption alg")
	}
}
