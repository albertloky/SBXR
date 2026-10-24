//go:build ignore

// Synthetic, inert Go tar/gzip compatibility fixture; never executed as a program.
package main

import (
	"archive/tar"
	"compress/gzip"
	"os"
)

func main() {
	f, e := os.Create("src/release_acquisition/testdata/go-single-member.tar.gz")
	if e != nil {
		panic(e)
	}
	g := gzip.NewWriter(f)
	t := tar.NewWriter(g)
	b := []byte("inert Go archive fixture\n")
	if e = t.WriteHeader(&tar.Header{Name: "sbxr", Typeflag: tar.TypeReg, Mode: 0755, Uid: 0, Gid: 0, Uname: "root", Gname: "root", Size: int64(len(b)), Format: tar.FormatUSTAR}); e != nil {
		panic(e)
	}
	if _, e = t.Write(b); e != nil {
		panic(e)
	}
	for _, e := range []error{t.Close(), g.Close(), f.Close()} {
		if e != nil {
			panic(e)
		}
	}
}
