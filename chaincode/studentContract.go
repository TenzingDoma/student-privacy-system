package main

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
)

// SmartContract manages student access permissions.
type SmartContract struct {
	contractapi.Contract
}

// StudentPermission represents access rights for a student record.
// Private student details will be stored separately in a database.

type StudentPermission struct {
	StudentID string `json:"studentID"`
	OwnerMSP  string `json:"ownerMSP"`
	OwnerID   string `json:"ownerID"`
}

// RegisterStudent registers a fictional student ID on the ledger.
// Only the designated organization can subsequently manage it.
func (s *SmartContract) RegisterStudent(
	ctx contractapi.TransactionContextInterface,
	studentID string,
) error {
	if studentID == "" {
		return fmt.Errorf("student ID cannot be empty")
	}

	existing, err := ctx.GetStub().GetState(studentID)
	if err != nil {
		return err
	}
	if existing != nil {
		return fmt.Errorf("student already registered")
	}

	mspID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return err
	}

	ownerID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return fmt.Errorf("failed to get user identity: %w", err)
	}

	record := fmt.Sprintf(
		`{"studentID":%q,"ownerMSP":%q,"ownerID":%q}`,
		studentID, mspID, ownerID,
	)

	return ctx.GetStub().PutState(
		studentID, []byte(record),
	)
}

func (s *SmartContract) CheckAccess(
	ctx contractapi.TransactionContextInterface,
	studentID string,
) (bool, error) {
	if studentID == "" {
		return false, fmt.Errorf("student ID cannot be empty")
	}

	data, err := ctx.GetStub().GetState(studentID)
	if err != nil {
		return false, err
	}
	if data == nil {
		return false, fmt.Errorf("student not found")
	}

	var permission StudentPermission
	if err := json.Unmarshal(data, &permission); err != nil {
		return false, err
	}

	requesterMSP, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return false, err
	}

	requesterID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return false, fmt.Errorf("failed to get requester identity: %w", err)
	}

	return requesterMSP == permission.OwnerMSP &&
		requesterID == permission.OwnerID, nil
}

func main() {
	chaincode, err := contractapi.NewChaincode(
		new(SmartContract),
	)
	if err != nil {
		panic(err)
	}

	if err := chaincode.Start(); err != nil {
		panic(err)
	}
}
