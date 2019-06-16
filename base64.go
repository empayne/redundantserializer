package main

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
)

// Inspired by https://stackoverflow.com/questions/28020070
func toBase64(m redundantStructure) (*string, error) {
	b := bytes.Buffer{}
	e := gob.NewEncoder(&b)

	// TODO: potential optimization by not calling gob.Register every time
	gob.Register(redundantStructure{})
	err := e.Encode(m)
	if err != nil {
		return nil, err
	}

	encoded := base64.StdEncoding.EncodeToString(b.Bytes())
	return &encoded, nil
}

// Inspired by https://stackoverflow.com/questions/28020070
func fromBase64(str string) (*redundantStructure, error) {
	m := redundantStructure{}
	by, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return nil, err
	}
	b := bytes.Buffer{}
	b.Write(by)
	d := gob.NewDecoder(&b)
	err = d.Decode(&m)
	if err != nil {
		return nil, err
	}
	return &m, nil
}
