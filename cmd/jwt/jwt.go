package main

// jwt either encodes or decodes stdin, writing to stdout using provided key
// data.
//
//
// Example:
//		# decode and verify a token
//		echo "" |jwt -dec -k rsa.pem
//		echo ""t

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/knq/jwt"
	"github.com/knq/pemutil"
)

var (
	flagEnc = flag.Bool("enc", false, "encode token from json data provided from stdin, or via name=value pairs passed on the command line")
	flagDec = flag.Bool("dec", false, "decode and verify token read from stdin using the provided key data")
	flagKey = flag.String("k", "", "path to PEM-encoded file containing key data")
	flagAlg = flag.String("alg", "", "override signing algorithm")
)

func main() {
	var err error

	// parse parameters
	flag.Parse()

	// make sure k parameter is specified
	if *flagKey == "" {
		fmt.Fprintln(os.Stderr, "error: must supply a key")
		os.Exit(1)
	}

	// inspect remaining args
	args := flag.Args()
	if len(args) > 0 && *flagDec {
		fmt.Fprintln(os.Stderr, "error: unknown args passed for -dec")
		os.Exit(1)
	}

	// if there are command line args and enc, then build js from them
	var in []byte
	if len(args) > 0 && *flagEnc {
		in, err = buildEncArgs(args)
	} else {
		in, err = ioutil.ReadAll(os.Stdin)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// read key data
	pem := pemutil.Store{}
	err = pemutil.PEM{*flagKey}.Load(pem)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}

	// determine alg
	var alg jwt.Algorithm
	if *flagAlg != "" {
		err = (&alg).UnmarshalText([]byte(*flagAlg))
	} else if *flagDec {
		alg, err = jwt.PeekAlgorithm(in)
	} else {
		alg, err = getAlgFromKeyData(pem)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// create signer
	signer, err := alg.New(pem)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// encode or decode
	var out []byte
	switch {
	case *flagDec:
		out, err = doDec(signer, in)

	case *flagEnc:
		out, err = doEnc(signer, in)

	default:
		err = errors.New("please specify -enc or -dec")
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	os.Stdout.Write(out)
}

// getSuitableAlgFromCurve inspects the key length in curve, and determines the
// corresponding jwt.Algorithm.
func getSuitableAlgFromCurve(curve elliptic.Curve) (jwt.Algorithm, error) {
	curveBitSize := curve.Params().BitSize

	// compute curve key len
	keyLen := curveBitSize / 8
	if curveBitSize%8 > 0 {
		keyLen++
	}

	// determine alg
	var alg jwt.Algorithm
	switch 2 * keyLen {
	case 64:
		alg = jwt.ES256
	case 96:
		alg = jwt.ES384
	case 132:
		alg = jwt.ES512

	default:
		return jwt.NONE, fmt.Errorf("invalid key length %d", keyLen)
	}

	return alg, nil
}

// getAlgFromKeyData determines the best jwt.Algorithm suitable based on the
// set of given crypto primitives in pem.
func getAlgFromKeyData(pem pemutil.Store) (jwt.Algorithm, error) {
	for _, v := range pem {
		// loop over crypto primitives in pemstore, and do type assertion. if
		// ecdsa.{PublicKey,PrivateKey} found, then use corresponding ESXXX as
		// algo. if rsa, then use DefaultRSAAlgorithm. if []byte, then use
		// DefaultHMACAlgorithm.
		switch k := v.(type) {
		case []byte:
			return jwt.HS512, nil

		case *ecdsa.PrivateKey:
			return getSuitableAlgFromCurve(k.Curve)

		case *ecdsa.PublicKey:
			return getSuitableAlgFromCurve(k.Curve)

		case *rsa.PrivateKey:
			return jwt.PS512, nil

		case *rsa.PublicKey:
			return jwt.PS512, nil
		}
	}

	return jwt.NONE, errors.New("cannot determine key type")
}

// buildEncArgs builds and encodes passed argument strings in the form of
// name=val as a json object.
func buildEncArgs(args []string) ([]byte, error) {
	m := make(map[string]interface{})

	// loop over args, splitting on '=', and attempt parsing of value
	for _, arg := range args {
		a := strings.SplitN(arg, "=", 2)
		var val interface{}

		// attempt to parse
		if len(a) == 1 { // assume bool, set as true
			val = true
		} else if u, err := strconv.ParseUint(a[1], 10, 64); err == nil {
			val = u
		} else if i, err := strconv.ParseInt(a[1], 10, 64); err == nil {
			val = i
		} else if f, err := strconv.ParseFloat(a[1], 64); err == nil {
			val = f
		} else if b, err := strconv.ParseBool(a[1]); err == nil {
			val = b
		} else if s, err := strconv.Unquote(a[1]); err == nil {
			val = s
		} else { // treat as string
			val = a[1]
		}

		m[a[0]] = val
	}

	return json.Marshal(m)
}

// UnstructuredToken is a jwt compatible token for encoding/decoding unknown
// jwt payloads.
type UnstructuredToken struct {
	Header    map[string]interface{} `json:"header" jwt:"header"`
	Payload   map[string]interface{} `json:"payload" jwt:"payload"`
	Signature []byte                 `json:"signature" jwt:"signature"`
}

// doDec decodes in as a JWT.
func doDec(signer jwt.Signer, in []byte) ([]byte, error) {
	var err error

	// decode token
	ut := UnstructuredToken{}
	err = signer.Decode(bytes.TrimSpace(in), &ut)
	if err != nil {
		return nil, err
	}

	// pretty format output
	out, err := json.MarshalIndent(&ut, "", "  ")
	if err != nil {
		return nil, err
	}

	return out, nil
}

// doEnc encodes in as the payload in a JWT.
func doEnc(signer jwt.Signer, in []byte) ([]byte, error) {
	var err error

	// make sure its valid json first
	m := make(map[string]interface{})
	err = json.Unmarshal(in, &m)
	if err != nil {
		return nil, err
	}

	// encode claims
	out, err := signer.Encode(&m)
	if err != nil {
		return nil, err
	}

	return out, nil
}
