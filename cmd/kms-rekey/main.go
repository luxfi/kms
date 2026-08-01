// Command kms-rekey moves a KMS store onto an at-rest encryption key.
//
// It is a separate binary on purpose. The server starts serving the moment it
// runs — it takes no subcommand — so a migration hidden behind an argv word in
// that binary is a migration one typo away from starting a second server on the
// data directory it is supposed to be copying. One binary, one job.
//
// Run it with the server STOPPED: ZapDB takes a directory lock, and a store
// being written while it is read is a store whose copy is missing records.
//
//	# plaintext store -> encrypted store
//	KMS_ENCRYPTION_KEY_B64=$(head -c 32 /dev/urandom | base64) \
//	  kms-rekey -from /data/kms -to /data/kms-encrypted
//
//	# rotate an already-encrypted store onto a new key
//	KMS_REKEY_FROM_B64=<old> KMS_ENCRYPTION_KEY_B64=<new> \
//	  kms-rekey -from /data/kms -to /data/kms-next
//
// The source is opened read-only and is never written. On success it prints the
// number of records in the destination; compare it against the source before
// pointing KMS_DATA_DIR at the result and deleting nothing until you have.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/luxfi/kms/pkg/atrest"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("kms-rekey: ")

	from := flag.String("from", os.Getenv("KMS_DATA_DIR"), "store to read (defaults to $KMS_DATA_DIR)")
	to := flag.String("to", "", "directory to write the re-encrypted store into (must be empty or absent)")
	flag.Parse()

	if *from == "" || *to == "" {
		flag.Usage()
		log.Fatal("-from and -to are both required")
	}

	dstKey, err := atrest.KeyFromEnv()
	if err != nil {
		log.Fatalf("%v", err)
	}
	srcKey, err := atrest.SourceKeyFromEnv()
	if err != nil {
		log.Fatalf("%v", err)
	}
	if len(srcKey) == 0 {
		log.Printf("source %s is being read as PLAINTEXT (%s is unset)", *from, atrest.SourceKeyEnv)
	}

	records, err := atrest.Rekey(*from, *to, srcKey, dstKey)
	if err != nil {
		log.Fatalf("%v", err)
	}

	fmt.Printf("%d records copied to %s, encrypted under %s\n", records, *to, atrest.KeyEnv)
	fmt.Printf("the source at %s is unchanged; verify the count before you point KMS_DATA_DIR at %s\n", *from, *to)
}
