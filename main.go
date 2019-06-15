package main

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"encoding/xml"
	"fmt"
)

type redundantStructure struct {
	XMLData  []byte
	JSONData []byte
}

// SerializableMap is used to define map[string]string <-> XML (un)marshalling,
// as Golang's 'encoding/xml' doesn't natively support this.
type SerializableMap map[string]string

func main() {
	type Foo struct {
		score string
		bio   string
	}
	testStruct := Foo{score: "1", bio: "text"}
	testMSS := map[string]string{"score": testStruct.score, "bio": testStruct.bio}

	serialized, err := serialize(testMSS)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(*serialized)
	}
}

func serialize(in SerializableMap) (*string, error) {
	xmlData, err := xml.MarshalIndent(in, "", "  ")
	if err != nil {
		return nil, err
	}

	jsonData, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}

	toSerialize := redundantStructure{xmlData, jsonData}
	return toGoB64(toSerialize)
}

// MarshalXML maps our SerializableMap to XML data.
// Taken from https://stackoverflow.com/questions/30928770
func (s SerializableMap) MarshalXML(e *xml.Encoder, start xml.StartElement) error {

	tokens := []xml.Token{start}

	for key, value := range s {
		t := xml.StartElement{Name: xml.Name{"", key}}
		tokens = append(tokens, t, xml.CharData(value), xml.EndElement{t.Name})
	}

	tokens = append(tokens, xml.EndElement{start.Name})

	for _, t := range tokens {
		err := e.EncodeToken(t)
		if err != nil {
			return err
		}
	}

	// flush to ensure tokens are written
	err := e.Flush()
	if err != nil {
		return err
	}

	return nil
}

// Go base64 encoder, inspired by https://stackoverflow.com/questions/28020070
func toGoB64(m redundantStructure) (*string, error) {
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
