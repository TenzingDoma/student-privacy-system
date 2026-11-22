
package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	_ "github.com/mattn/go-sqlite3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Student struct {
	ID    string  `json:"id"`
	Name  string  `json:"name"`
	Major string  `json:"major"`
	GPA   float64 `json:"gpa"`
}

func main() {
	org := flag.Int("org", 1, "Fabric organization: 1 or 2")
	studentID := flag.String("student", "STU001", "Student ID")
	flag.Parse()

	if *org != 1 && *org != 2 {
		exitError(fmt.Errorf("organization must be 1 or 2"))
	}

	db, err := sql.Open("sqlite3", "./students.db")
	if err != nil {
		exitError(err)
	}
	defer db.Close()

	if err := initializeDatabase(db); err != nil {
		exitError(err)
	}

	fmt.Println("Student Privacy Management System")
	fmt.Println("---------------------------------")
	fmt.Printf("Demo organization: Org%d\n", *org)
	fmt.Printf("Requested student: %s\n", *studentID)

	network, connection, gateway, err := connectFabric(*org)
	if err != nil {
		exitError(err)
	}
	defer connection.Close()
	defer gateway.Close()

	contract := network.GetContract("studentprivacy")

	fmt.Println("Checking blockchain authorization...")

	result, err := contract.EvaluateTransaction(
		"CheckAccess", *studentID,
	)
	if err != nil {
		exitError(fmt.Errorf("blockchain check failed: %w", err))
	}

	if strings.TrimSpace(string(result)) != "true" {
		fmt.Println("ACCESS DENIED")
		fmt.Println("No student information was retrieved.")
		return
	}

	fmt.Println("ACCESS GRANTED")

	var student Student

	err = db.QueryRow(
		`SELECT id, name, major, gpa
		 FROM students WHERE id = ?`,
		*studentID,
	).Scan(
		&student.ID,
		&student.Name,
		&student.Major,
		&student.GPA,
	)

	if errors.Is(err, sql.ErrNoRows) {
		fmt.Println("Student not found in local database.")
		return
	}
	if err != nil {
		exitError(err)
	}

	output, err := json.MarshalIndent(student, "", "  ")
	if err != nil {
		exitError(err)
	}

	fmt.Println("Authorized student record:")
	fmt.Println(string(output))
}

func initializeDatabase(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS students (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			major TEXT NOT NULL,
			gpa REAL NOT NULL
				CHECK(gpa >= 0 AND gpa <= 4)
		)
	`)
	if err != nil {
		return err
	}

	// Fictional demonstration data only.
	_, err = db.Exec(`
		INSERT OR IGNORE INTO students
			(id, name, major, gpa)
		VALUES
			('STU001', 'Alex Morgan', 'Computer Science', 3.85),
			('STU002', 'Jordan Lee', 'Mathematics', 3.70),
			('STU003', 'Taylor Kim', 'Data Science', 3.92)
	`)
	return err
}

func connectFabric(
	org int,
) (*client.Network, *grpc.ClientConn, *client.Gateway, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil, nil, err
	}

	base := filepath.Join(
		home, "fabric-projects", "fabric-samples",
		"test-network", "organizations",
		"peerOrganizations",
	)

	orgName := fmt.Sprintf("org%d.example.com", org)
	mspID := fmt.Sprintf("Org%dMSP", org)
	peerName := "peer0." + orgName

	port := 7051
	if org == 2 {
		port = 9051
	}

	orgPath := filepath.Join(base, orgName)
	mspPath := filepath.Join(
		orgPath, "users",
		"Admin@"+orgName, "msp",
	)

	certPEM, err := os.ReadFile(
filepath.Join(mspPath, "signcerts", "Admin@"+orgName+"-cert.pem"),	)
	if err != nil {
		return nil, nil, nil, err
	}

	cert, err := identity.CertificateFromPEM(certPEM)
	if err != nil {
		return nil, nil, nil, err
	}

	id, err := identity.NewX509Identity(mspID, cert)
	if err != nil {
		return nil, nil, nil, err
	}

	keyDir := filepath.Join(mspPath, "keystore")
	entries, err := os.ReadDir(keyDir)
	if err != nil {
		return nil, nil, nil, err
	}

	var privateKey crypto.PrivateKey
	foundKey := false

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		keyPEM, readErr := os.ReadFile(
			filepath.Join(keyDir, entry.Name()),
		)
		if readErr != nil {
			return nil, nil, nil, readErr
		}

		privateKey, err = identity.PrivateKeyFromPEM(keyPEM)
		if err == nil {
			foundKey = true
			break
		}
	}

	if !foundKey {
		return nil, nil, nil,
			fmt.Errorf("no valid private key found")
	}

	signer, err := identity.NewPrivateKeySign(privateKey)
	if err != nil {
		return nil, nil, nil, err
	}

	tlsPath := filepath.Join(
		orgPath, "peers", peerName,
		"tls", "ca.crt",
	)

	tlsPEM, err := os.ReadFile(tlsPath)
	if err != nil {
		return nil, nil, nil, err
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(tlsPEM) {
		return nil, nil, nil,
			fmt.Errorf("invalid peer TLS certificate")
	}

	tlsConfig := &tls.Config{
		RootCAs:    roots,
		ServerName: peerName,
		MinVersion: tls.VersionTLS12,
	}

	address := fmt.Sprintf("localhost:%d", port)

	ctx, cancel := context.WithTimeout(
		context.Background(), 10*time.Second,
	)
	defer cancel()

	connection, err := grpc.DialContext(
		ctx,
		address,
		grpc.WithTransportCredentials(
			credentials.NewTLS(tlsConfig),
		),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, nil, nil, err
	}

	gateway, err := client.Connect(
		id,
		client.WithSign(signer),
		client.WithClientConnection(connection),
		client.WithEvaluateTimeout(10*time.Second),
	)
	if err != nil {
		connection.Close()
		return nil, nil, nil, err
	}

	network := gateway.GetNetwork("mychannel")

	return network, connection, gateway, nil
}

func exitError(err error) {
	fmt.Fprintln(os.Stderr, "ERROR:", err)
	os.Exit(1)
}
