package basecodec

import (
	"crypto/rand"
	"fmt"
	"testing"
)

var base36BenchmarkResult []byte

func BenchmarkLowerBase36Frame(b *testing.B) {
	for _, size := range []int{128, 512} {
		data := make([]byte, size)
		if _, err := rand.Read(data); err != nil {
			b.Fatal(err)
		}
		encoded := EncodeLowerBase36Bytes(data)
		encodedString := string(encoded)
		b.Run(fmt.Sprintf("EncodeBytes/%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				base36BenchmarkResult = EncodeLowerBase36Bytes(data)
			}
		})
		b.Run(fmt.Sprintf("DecodeBytes/%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var err error
				base36BenchmarkResult, err = DecodeLowerBase36(encoded)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(fmt.Sprintf("DecodeString/%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var err error
				base36BenchmarkResult, err = DecodeLowerBase36String(encodedString)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkEncodeLowerBase36_Large(b *testing.B) {
	data := make([]byte, 512)
	rand.Read(data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EncodeLowerBase36(data)
	}
}

func BenchmarkDecodeLowerBase36_Large(b *testing.B) {
	data := make([]byte, 512)
	rand.Read(data)
	encoded := EncodeLowerBase36(data)
	encodedBytes := []byte(encoded)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DecodeLowerBase36(encodedBytes)
	}
}
