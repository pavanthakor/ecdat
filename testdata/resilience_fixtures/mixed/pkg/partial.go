package pkg

import "crypto/md5"

func ok() { md5.New() }

// Deliberately broken below. Semgrep's Go parser recovers PARTIALLY: the MD5
// above is still reported, and the file is a coverage gap all the same.
func broken( {{{
