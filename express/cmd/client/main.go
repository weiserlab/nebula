// Heavily based on Express evaluation code @ https://github.com/SabaEskandarian/Express
//   - see also: https://www.usenix.org/system/files/sec21-eskandarian.pdf
//   - original source code based on denji/golang-tls

package main

/*
#cgo CFLAGS: -O2 -I/usr/local/include
#cgo LDFLAGS: -lcrypto -lm -L/usr/local/lib
#include "../../pkg/dpf.h"
#include "../../pkg/okvClient.h"
#include "../../pkg/dpf.c"
#include "../../pkg/okvClient.c"
*/
import "C"
import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"golang.org/x/crypto/nacl/box"
	//	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	//"sync"
	//"time"
	"unsafe"
)

// connection message types
const (
	NEW_ROW int = iota
	WRITE
)

func main() {

	log.SetFlags(log.Lshortfile)

	// parse configuration
	var leaderIP string
	var followerIP string
	var dataSize, numThreads, numExistingRows int

	flag.StringVar(&leaderIP, "leaderIP", "localhost:4442", "IP:port of primary leader server")
	flag.StringVar(&followerIP, "followerIP", "localhost:4443", "IP:port of secondary follower server")
	flag.IntVar(&dataSize, "dataSize", 1024, "size of each mailbox")
	flag.IntVar(&numThreads, "numThreads", 8, "number of client threads")
	flag.IntVar(&numExistingRows, "numExistingRows", 1000, "number of existing rows on server")

	flag.Parse()

	log.Printf("starting client for %v-byte messages...\n\texpecting servers at %v and %v\n",
		dataSize, leaderIP, followerIP)

	C.initializeClient(C.int(numThreads))
	// XXX probably not entirely correct
	for i := 0; i < numExistingRows; i++ {
		rowAKey := (*C.uchar)(C.malloc(16))
		rowBKey := (*C.uchar)(C.malloc(16))
		C.prepNewRow(C.int(dataSize), rowAKey, rowBKey)
	}

	// XXX using deterministic keys for testing
	_, clientSecretKey, err := box.GenerateKey(strings.NewReader(strings.Repeat("c", 10000)))
	if err != nil {
		log.Fatal(err)
	}
	s2PublicKey, _, err := box.GenerateKey(strings.NewReader(strings.Repeat("b", 10000)))
	if err != nil {
		log.Fatal(err)
	}
	auditorPublicKey, _, err := box.GenerateKey(strings.NewReader(strings.Repeat("a", 10000)))
	if err != nil {
		log.Fatal(err)
	}
	_ = auditorPublicKey

	reader := bufio.NewReader(os.Stdin)
	for {
		input, _ := reader.ReadString('\n')
		words := strings.Fields(input)

		switch words[0] {
		case "0": // new mailbox, no other inputs
			go func() {
				idx, addr := addRow(leaderIP, followerIP, dataSize)
				// print <local id> <virtual address>
				fmt.Printf("%v %v\n", idx, hex.EncodeToString(addr))
			}()
		case "1": // mailbox write, <local id> <payload>
			if len(words) != 3 {
				log.Println("expected write format `1 <32-bit row id> <1024 byte payload hex string>`, but got this many arguments:", len(words))
				continue
			}

			go func() {
				data := make([]byte, dataSize)
				payload_bytes, err := hex.DecodeString(words[2])
				if err != nil {
					log.Println("error:", err)
					return
				}
				copy(data, payload_bytes)

				idx, _ := strconv.Atoi(words[1])
				if err != nil {
					log.Println("error:", err)
					return
				}
				writeRow(idx, data, leaderIP, s2PublicKey, clientSecretKey)
			}()
		default:
			log.Printf("warning: got unexpected input operation code %s\n", words[0])
			continue
		}
	}
}

func writeRow(localIndex int, data []byte, serverIP string, s2PublicKey, clientSecretKey *[32]byte) {

	log.Println("writing row")

	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	log.Println("dialing...")
	serverConn, err := tls.Dial("tcp", serverIP, conf)
	if err != nil {
		log.Fatal(err)
	}
	defer serverConn.Close()
	log.Printf("connected to server\n")

	threadNum := 0

	dataSize := len(data)
	querySize := make([]byte, 4)

	cIntQuerySize := C.int(byteToInt(querySize))
	var dpfQueryA *C.uchar
	var dpfQueryB *C.uchar

	C.prepQuery(C.int(threadNum), C.int(localIndex), getPtrToBuffer(data, 0), C.int(dataSize), &cIntQuerySize, &dpfQueryA, &dpfQueryB)

	writeBytesToConn(serverConn, intToByte(WRITE)[0:1])

	intQuerySize := int(cIntQuerySize)
	msg := append(intToByte(intQuerySize), intToByte(dataSize)...)

	// prep query for leader server A
	sendQuery := C.GoBytes(unsafe.Pointer(dpfQueryA), C.int(intQuerySize))
	msg = append(msg, sendQuery...)

	// prep and box query for follower server B
	serverBPlaintext := C.GoBytes(unsafe.Pointer(dpfQueryB), C.int(intQuerySize))

	var nonce [24]byte
	_, err = rand.Read(nonce[:])
	if err != nil {
		log.Fatal("couldn't get randomness for nonce")
	}

	serverBCiphertext := box.Seal(nonce[:], serverBPlaintext, &nonce, s2PublicKey, clientSecretKey)

	msg = append(msg, serverBCiphertext...)

	// send to primary server
	writeBytesToConn(serverConn, msg)

	/* --- now, do auditing protocol --- */

	// read seed from primary
	seed := readBytesFromConn(serverConn, 16)

	// prep message for auditor
	outputsA := (*C.uchar)(C.malloc(C.ulong(160)))
	outputsB := (*C.uchar)(C.malloc(C.ulong(160)))

	C.prepAudit(C.int(threadNum), C.int(localIndex), getPtrToBuffer(seed, 0), outputsA, outputsB, dpfQueryA, dpfQueryB)

	auditPlaintextA := C.GoBytes(unsafe.Pointer(outputsA), C.int(160))
	auditPlaintextB := C.GoBytes(unsafe.Pointer(outputsB), C.int(160))

	// nonce for box
	_, err = rand.Read(nonce[:])
	if err != nil {
		log.Fatal("couldn't get randomness for nonce")
	}

	s2AuditCiphertext := box.Seal(nonce[:], auditPlaintextB, &nonce, s2PublicKey, clientSecretKey)

	msg = append(auditPlaintextA, s2AuditCiphertext...)
	writeBytesToConn(serverConn, msg)

	C.free(unsafe.Pointer(outputsA))
	C.free(unsafe.Pointer(outputsB))
	C.free(unsafe.Pointer(dpfQueryA))
	C.free(unsafe.Pointer(dpfQueryB))

	log.Printf("waiting for done\n")
	done := readBytesFromConn(serverConn, 4)
	log.Printf("write done with code %v!\n", done)
}

func addRow(leaderIP, followerIP string, dataSize int) (int, []byte) {

	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	connLeader, err := tls.Dial("tcp", leaderIP, conf)
	if err != nil {
		log.Fatal(err)
	}
	defer connLeader.Close()
	log.Printf("connected to leader server\n")

	connFollower, err := tls.Dial("tcp", followerIP, conf)
	if err != nil {
		log.Fatal(err)
	}
	defer connFollower.Close()
	log.Printf("connected to follower server\n")

	rowAKey := (*C.uchar)(C.malloc(16))
	rowBKey := (*C.uchar)(C.malloc(16))
	C.prepNewRow(C.int(dataSize), rowAKey, rowBKey)

	// tell servers we're adding a new row
	writeBytesToConn(connLeader, intToByte(NEW_ROW)[0:1])
	writeBytesToConn(connFollower, intToByte(NEW_ROW)[0:1])

	// tell servers we just want to add one entry
	writeBytesToConn(connLeader, intToByte(1))
	writeBytesToConn(connFollower, intToByte(1))

	// send row size
	writeBytesToConn(connLeader, intToByte(dataSize))
	writeBytesToConn(connFollower, intToByte(dataSize))

	// send row keys
	writeBytesToConn(connLeader, C.GoBytes(unsafe.Pointer(rowAKey), 16))
	writeBytesToConn(connFollower, C.GoBytes(unsafe.Pointer(rowBKey), 16))

	mailboxIdx := byteToInt(readBytesFromConn(connLeader, 4))
	mailboxAddr := readBytesFromConn(connLeader, 16)

	C.addAddr(C.int(mailboxIdx), getPtrToBuffer(mailboxAddr, 0))

	return mailboxIdx, mailboxAddr
}

/* Utility functions */

func readBytesFromConn(conn net.Conn, n int) []byte {
	payload := make([]byte, n)
	for count := 0; count < n; {
		nRead, err := conn.Read(payload[count:])
		count += nRead
		if err != nil && count != n {
			log.Fatal(err, n, count)
		}
	}

	return payload
}

func writeBytesToConn(conn net.Conn, payload []byte) {
	nWritten, err := conn.Write(payload)
	if err != nil || nWritten != len(payload) {
		log.Fatal(err, nWritten)
	}
}

func getPtrToBuffer(buf []byte, idx int) *C.uchar {
	return (*C.uchar)(&buf[idx])
}

func byteToInt(bytes []byte) int {
	nBytes := len(bytes)
	if nBytes > 4 {
		nBytes = 4
	}

	x := 0
	for i := 0; i < nBytes; i++ {
		x += int(bytes[i]) << (i * 8)
	}
	return x
}

func intToByte(x int) []byte {
	bytes := make([]byte, 4)
	for i := 0; i < 4; i++ {
		bytes[i] = byte((x >> (i * 8)) & 0xff)
	}
	return bytes
}