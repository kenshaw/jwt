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

	"github.com/knq/jwt"
	"github.com/knq/pemutil"
)

var (
	flagEnc      = flag.Bool("enc", false, "encode stdin")
	flagDec      = flag.Bool("dec", false, "decode stdin")
	flagKey      = flag.String("k", "", "path to PEM-encoded file containing key data")
	flagAlg      = flag.String("alg", "", "use specified algorithm")
	flagNoVerify = flag.Bool("noverify", false, "only decode data, do not encode")
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

	// read key data
	pem := pemutil.Store{}
	err = pemutil.PEM{*flagKey}.Load(pem)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}

	// set key
	var alg jwt.Algorithm

	// get alg from key
	if *flagAlg == "" {
		alg, err = getAlgFromKeyData(pem)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	} else {
		// attempt to decode alg
		err = json.Unmarshal([]byte(`"`+*flagAlg+`"`), &alg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	}

	// create signer
	signer := alg.New(pem)

	// read stdin
	in, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v", err)
		os.Exit(1)
	}

	// encode, decode, or error
	switch {
	case *flagDec:
		err = doDec(signer, in)

	case *flagEnc:
		err = doEnc(signer, in)

	default:
		err = errors.New("please specify -enc or -dec")
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// getSuitableAlgFromCurve inspects the key length in curve, and determines the
// jwt.Algorithm to use for it.
func getSuitableAlgFromCurve(curve elliptic.Curve) (jwt.Algorithm, error) {
	curveBitSize := curve.Params().BitSize

	// compute key len
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

// unstructured token
type UnstructuredToken struct {
	Header    map[string]interface{} `json:"header" jwt:"header"`
	Payload   map[string]interface{} `json:"payload" jwt:"payload"`
	Signature []byte                 `json:"signature" jwt:"signature"`
}

// do decode
func doDec(signer jwt.Signer, in []byte) error {
	var err error

	// create our token
	ut := UnstructuredToken{
		Header:  make(map[string]interface{}),
		Payload: make(map[string]interface{}),
	}

	// decode token
	err = signer.Decode(bytes.TrimSpace(in), &ut)
	if err != nil {
		return err
	}

	// pretty format output
	out, err := json.MarshalIndent(&ut, "", "  ")
	if err != nil {
		return err
	}

	// write
	os.Stdout.Write(out)

	return nil
}

// do encode
func doEnc(signer jwt.Signer, in []byte) error {
	var err error

	// make sure its valid json first
	m := make(map[string]interface{})
	err = json.Unmarshal(in, &m)
	if err != nil {
		return err
	}

	// encode claims
	out, err := signer.Encode(&m)
	if err != nil {
		return err
	}

	// write
	os.Stdout.Write(out)
	return nil
}
