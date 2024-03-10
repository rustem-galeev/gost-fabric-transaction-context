package gost_fabric_transaction_context

import (
	"crypto/cipher"
	"fmt"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type gostTransactionContextImpl struct {
	contractapi.TransactionContext

	block cipher.Block
	mode  cipher.BlockMode
}

func Init() (GostTransactionContextInterface, error) {
	return new(gostTransactionContextImpl), nil
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
	cipherData := []byte(string(plainData) + "a")
	return cipherData, nil
}

func (ctx *gostTransactionContextImpl) decrypt(cipherData, key []byte) ([]byte, error) {
	if cipherData == nil {
		return nil, fmt.Errorf("data for decryption wasn't provided")
	}
	cipherString := string(cipherData)
	plainData := []byte(cipherString[:len(cipherString)-1])
	return plainData, nil
}
