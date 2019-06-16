package main

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"reflect"

	"github.com/lestrrat-go/libxml2"
	"github.com/lestrrat-go/libxml2/parser"
)

type redundantStructure struct {
	XMLData  string
	JSONData string
}

type xmlMapEntry struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

// SerializableMap is used to define map[string]string <-> XML (un)marshalling,
// as Golang's 'encoding/xml' doesn't natively support this.
type SerializableMap map[string]string

func main() {
	type Foo struct {
		score string
		bio   string
		car   string
	}
	testStruct := Foo{score: "27", bio: "text", car: "asdsad"}
	testMSS := map[string]string{"score": testStruct.score, "bio": testStruct.bio, "car": testStruct.car}

	serialized, err := serialize(testMSS)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(*serialized)
	}

	testB64String := "Of+BAwEBEnJlZHVuZGFudFN0cnVjdHVyZQH/ggABAgEHWE1MRGF0YQEMAAEISlNPTkRhdGEBDAAAAP+P/4IBXjxTZXJpYWxpemFibGVNYXA+CiAgPGJpbz50ZXh0PC9iaW8+CiAgPGNhcj5hc2RzYWQ8L2Nhcj4KICA8c2NvcmU+Mjc8L3Njb3JlPgo8L1NlcmlhbGl6YWJsZU1hcD4BKnsiYmlvIjoidGV4dCIsImNhciI6ImFzZHNhZCIsInNjb3JlIjoiMjcifQA=" //"Of+BAwEBEnJlZHVuZGFudFN0cnVjdHVyZQH/ggABAgEHWE1MRGF0YQEMAAEISlNPTkRhdGEBDAAAAGr/ggFJPFNlcmlhbGl6YWJsZU1hcD4KICA8c2NvcmU+MTwvc2NvcmU+CiAgPGJpbz50ZXh0PC9iaW8+CjwvU2VyaWFsaXphYmxlTWFwPgEaeyJiaW8iOiJ0ZXh0Iiwic2NvcmUiOiIxIn0A"

	deserialized, err := deserialize(testB64String)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(deserialized)
	}
}

func serialize(in SerializableMap) (*string, error) {
	xmlData, err := xml.Marshal(in)
	if err != nil {
		return nil, err
	}

	jsonData, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}

	toSerialize := redundantStructure{string(xmlData), string(jsonData)}
	return toBase64(toSerialize)
}

func deserialize(in string) (SerializableMap, error) {
	base64Decoded, err := fromBase64(in)
	if err != nil {
		return nil, err
	}

	xmlMap, err := getDeserializedXMLMap(base64Decoded.XMLData)
	if err != nil {
		return nil, err
	}

	var jsonMap SerializableMap
	err = json.Unmarshal([]byte(base64Decoded.JSONData), &jsonMap)

	if !reflect.DeepEqual(xmlMap, jsonMap) {
		errorMessage := fmt.Sprintf("Deserialized XML (%v) and JSON (%v) are not equal!", xmlMap, jsonMap)
		return nil, errors.New(errorMessage)
	}

	// arbitrarily return xmlMap over jsonMap; we already know they're equal
	return xmlMap, nil
}

func getDeserializedXMLMap(XMLData string) (SerializableMap, error) {
	expandedXMLString, err := expandXMLString(XMLData)
	if err != nil {
		return nil, err
	}

	var xmlMap SerializableMap
	err = xml.Unmarshal([]byte(*expandedXMLString), &xmlMap)
	if err != nil {
		return nil, err
	}

	return xmlMap, nil
}

// MarshalXML maps our SerializableMap to XML data.
// Inspired by https://blog.csdn.net/tangtong1/article/details/80418286
func (m SerializableMap) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	if len(m) == 0 {
		return nil
	}

	err := e.EncodeToken(start)
	if err != nil {
		return err
	}

	for k, v := range m {
		e.Encode(xmlMapEntry{XMLName: xml.Name{Local: k}, Value: v})
	}

	return e.EncodeToken(start.End())
}

// UnmarshalXML maps our XML data back to a SerializableMap.
// Inspired by https://blog.csdn.net/tangtong1/article/details/80418286
func (m *SerializableMap) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	*m = SerializableMap{}
	for {
		var e xmlMapEntry

		err := d.Decode(&e)
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		(*m)[e.XMLName.Local] = e.Value
	}
	return nil
}

func expandXMLString(xmlString string) (*string, error) {
	xmlString = `<?xml version="1.0" ?><!DOCTYPE SerializableMap [  <!ELEMENT SerializableMap ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><SerializableMap><bio>&xxe;</bio><car>asdsa</car><score>27</score></SerializableMap>`

	doc, err := libxml2.ParseString(xmlString, parser.XMLParseNoEnt)
	defer doc.Free()
	if err != nil {
		return nil, err
	}

	xmlStr := doc.Dump(false)
	return &xmlStr, nil
}

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
