package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

const ANDROID_PUBKEY_MODULUS_SIZE = 256
const ANDROID_PUBKEY_ENCODED_SIZE = ANDROID_PUBKEY_MODULUS_SIZE + 8

func main() {

	s := big.NewInt(0)
	pbulicKey := "AIezam19UJH0/CJr27n6SfKL2XwkQoU8vIsR5WASNVXZFsloOmDlGozikOTw7nzir2GmviD7q85A30YPLA6n3+7vGLUBfRakzg1bZ5l3lr8P8OBM2FcQEtb8VAlMmVs3AixHyY/GdbfpOhvW5L2RIkkIZ1ojlTKqCFROWSfJlxPFcAVrkFqk8OAMy5i5YMfEBtjyFemyGQbZEReQOQd4JP5eV2kshpuElhgIEhhEcOxdeVuqALbaBDFiiP/3+pWVSf6YQOP+5QJ3VCJdSv3tjCY2hkiR7V89OqOwCr1C9fvxzO1cOr4dgPzNUKC95ee/u/HjOXyC2XhJloyJ6O/24I0="
	dd, _ := base64.StdEncoding.DecodeString(pbulicKey)
	s.SetBytes(dd)
	buf, err := encodeRSAPublicKey(s, 65537)
	fmt.Printf("buf:%+v err:%v\r\n\r\n", buf, err)

	okData := "QAAAALsdor6N4Pbv6ImMlkl42YJ8OePxu7/n5b2gUM38gB2+OlztzPH79UK9CrCjOj1f7ZFIhjYmjO39Sl0iVHcC5f7jQJj+SZWV+vf/iGIxBNq2AKpbeV3scEQYEggYloSbhixpV17+JHgHOZAXEdkGGbLpFfLYBsTHYLmYywzg8KRakGsFcMUTl8knWU5UCKoylSNaZwhJIpG95NYbOum3dcaPyUcsAjdbmUwJVPzWEhBX2Ezg8A+/lneZZ1sNzqQWfQG1GO/u36cOLA9G30DOq/sgvqZhr+J87vDkkOKMGuVgOmjJFtlVNRJg5RGLvDyFQiR82YvySfq522si/PSRUH1tarOHp/P3InQj8DL6OrfLwrVGNE/MpW/E+qVAIzzrfDETZ44IDvPY2wM//ykgXRXNszOwvTS/Wtqc03cEUoQ4E6kLA42Ym0nrti7TuFPZbdqNJ1JYLwPvDV1Q6zf5eEcaQvVu+dElJ0J8/6FCCVboTBxV1yYNjZ0z8cVS0rZutfT7cBJGrEbMiVkWnqC/VegqySn/Bf+eWy9nygqCDRlp5n6fY0vq+RdyxAfGU+IXgDgw6SxoRE4imgoGzTu5cauhI8NgppxOJlHALcIoVudtBtTxEpo1ie9nsT5lIKL5pRNpN8jsJguExq6Q5vbqBLCADcujW1gbuComgBBnmCKKGtxCNgEAAQA="
	okBuf, _ := base64.StdEncoding.DecodeString(okData)
	fmt.Printf("okBuf:%+v err:%v\r\n", okBuf, err)
}

func encodeRSAPublicKey(publicKeyN *big.Int, publicKeyE int) ([]byte, error) {
	modulusBytes := publicKeyN.Bytes()
	if len(modulusBytes) < ANDROID_PUBKEY_MODULUS_SIZE {
		return nil, errors.New("Invalid key length")
	}

	var keyStruct bytes.Buffer
	// Store the modulus size.

	binary.Write(&keyStruct, binary.LittleEndian, uint32(ANDROID_PUBKEY_MODULUS_SIZE/4))

	// Compute and store n0inv = -1 / N[0] mod 2^32.
	r32 := big.NewInt(1).Lsh(big.NewInt(1), 32)
	n0 := big.NewInt(0).SetBytes(modulusBytes)
	n0inv := big.NewInt(0).Mod(n0, r32)
	n0inv = n0inv.ModInverse(n0inv, r32)
	n0inv = r32.Sub(r32, n0inv)
	binary.Write(&keyStruct, binary.LittleEndian, uint32(n0inv.Int64()))

	// Store the modulus.
	modulusLittleEndian := bigEndianToLittleEndianPadded(ANDROID_PUBKEY_MODULUS_SIZE, modulusBytes)

	keyStruct.Write(modulusLittleEndian)

	// Compute and store rr = (2^(rsa_size)) ^ 2 mod N.
	rr := big.NewInt(1).Lsh(big.NewInt(1), ANDROID_PUBKEY_MODULUS_SIZE*8)
	rr = rr.Exp(rr, big.NewInt(2), publicKeyN)
	rrLittleEndian := bigEndianToLittleEndianPadded(ANDROID_PUBKEY_MODULUS_SIZE, rr.Bytes())
	keyStruct.Write(rrLittleEndian)

	// Store the exponent.
	binary.Write(&keyStruct, binary.LittleEndian, uint32(publicKeyE))
	return keyStruct.Bytes(), nil
}
func bigEndianToLittleEndianPadded(size int, data []byte) []byte {
	result := make([]byte, size)
	for i, j := 0, len(data)-1; i < size && j >= 0; i, j = i+1, j-1 {
		result[i] = data[j]
	}
	return result
}

/*


I/System.out: getModulus:AIezam19UJH0/CJr27n6SfKL2XwkQoU8vIsR5WASNVXZFsloOmDlGozikOTw7nzir2GmviD7q85A30YPLA6n3+7vGLUBfRakzg1bZ5l3lr8P8OBM2FcQEtb8VAlMmVs3AixHyY/GdbfpOhvW5L2RIkkIZ1ojlTKqCFROWSfJlxPFcAVrkFqk8OAMy5i5YMfEBtjyFemyGQbZEReQOQd4JP5eV2kshpuElhgIEhhEcOxdeVuqALbaBDFiiP/3+pWVSf6YQOP+5QJ3VCJdSv3tjCY2hkiR7V89OqOwCr1C9fvxzO1cOr4dgPzNUKC95ee/u/HjOXyC2XhJloyJ6O/24I0=
I/System.out: e:65537
I/System.out: keyStruct:QAAAALsdor6N4Pbv6ImMlkl42YJ8OePxu7/n5b2gUM38gB2+OlztzPH79UK9CrCjOj1f7ZFIhjYmjO39Sl0iVHcC5f7jQJj+SZWV+vf/iGIxBNq2AKpbeV3scEQYEggYloSbhixpV17+JHgHOZAXEdkGGbLpFfLYBsTHYLmYywzg8KRakGsFcMUTl8knWU5UCKoylSNaZwhJIpG95NYbOum3dcaPyUcsAjdbmUwJVPzWEhBX2Ezg8A+/lneZZ1sNzqQWfQG1GO/u36cOLA9G30DOq/sgvqZhr+J87vDkkOKMGuVgOmjJFtlVNRJg5RGLvDyFQiR82YvySfq522si/PSRUH1tarOHp/P3InQj8DL6OrfLwrVGNE/MpW/E+qVAIzzrfDETZ44IDvPY2wM//ykgXRXNszOwvTS/Wtqc03cEUoQ4E6kLA42Ym0nrti7TuFPZbdqNJ1JYLwPvDV1Q6zf5eEcaQvVu+dElJ0J8/6FCCVboTBxV1yYNjZ0z8cVS0rZutfT7cBJGrEbMiVkWnqC/VegqySn/Bf+eWy9nygqCDRlp5n6fY0vq+RdyxAfGU+IXgDgw6SxoRE4imgoGzTu5cauhI8NgppxOJlHALcIoVudtBtTxEpo1ie9nsT5lIKL5pRNpN8jsJguExq6Q5vbqBLCADcujW1gbuComgBBnmCKKGtxCNgEAAQA=
I/System.out: Using default TLSv1.3 provider...
I/System.out: [socket]:check permission begin!


*/
