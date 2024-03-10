package gost_fabric_transaction_context

import (
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type GostTransactionContextInterface interface {
	contractapi.SettableTransactionContextInterface
	contractapi.TransactionContextInterface

	PutState(string, []byte, []byte) error
	GetState(string, []byte) ([]byte, error)
}
