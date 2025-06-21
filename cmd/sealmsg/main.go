package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"

	sm "github.com/takanoriyanagitani/go-seal-msg"
	. "github.com/takanoriyanagitani/go-seal-msg/util"
)

var getEnvByKey func(string) IO[string] = Lift(
	func(key string) (string, error) {
		val, found := os.LookupEnv(key)
		switch found {
		case true:
			return val, nil
		default:
			return "", fmt.Errorf("env var %s missing", key)
		}
	},
)

var secretKeyLocation IO[string] = getEnvByKey("ENV_SECRET_KEY_LOCATION")

func filename2bytesLimited(limit int64) func(string) IO[[]byte] {
	return Lift(func(filename string) ([]byte, error) {
		f, e := os.Open(filename)
		if nil != e {
			return nil, e
		}
		defer f.Close()

		limited := &io.LimitedReader{
			R: f,
			N: limit,
		}

		var buf bytes.Buffer
		_, e = io.Copy(&buf, limited)
		return buf.Bytes(), e
	})
}

var secretKey IO[[]byte] = Bind(
	secretKeyLocation,
	filename2bytesLimited(32),
)

var key1time IO[sm.OneTimeKey] = Bind(
	secretKey,
	Lift(func(raw []byte) (sm.OneTimeKey, error) {
		var buf [32]byte
		copy(buf[:], raw)
		skey := sm.SymmetricKey(buf)
		return sm.OneTimeKey(skey), nil
	}),
)

var plainTxtLocation IO[string] = getEnvByKey("ENV_PLAIN_TXT_LOCATION")

var plainTxtMaxSize IO[int] = Bind(
	getEnvByKey("ENV_PLAIN_TXT_MAX_SIZE"),
	Lift(strconv.Atoi),
).Or(Of(1048576))

var plainTxt IO[[]byte] = Bind(
	plainTxtLocation,
	filename2bytesLimited(
		int64(
			plainTxtMaxSize.UnwrapOr(
				context.Background(),
				func() int { return 1048576 },
			),
		),
	),
)

var printBytes func([]byte) IO[Void] = Lift(
	func(dat []byte) (Void, error) {
		_, e := os.Stdout.Write(dat)
		return Empty, e
	},
)

var sub IO[Void] = Bind(
	Bind(
		key1time,
		func(key sm.OneTimeKey) IO[[]byte] {
			return Bind(
				plainTxt,
				Lift(key.Seal),
			)
		},
	),
	printBytes,
)

func main() {
	_, e := sub(context.Background())
	if nil != e {
		log.Printf("%v\n", e)
	}
}
