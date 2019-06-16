package main

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"reflect"
)

type redundantStructure struct {
	XMLData  string
	JSONData string
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
	testStruct := Foo{score: "27", bio: "text"}
	testMSS := map[string]string{"score": testStruct.score, "bio": testStruct.bio}

	serialized, err := serialize(testMSS)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(*serialized)
	}

	testB64String := "Of+BAwEBEnJlZHVuZGFudFN0cnVjdHVyZQH/ggABAgEHWE1MRGF0YQEMAAEISlNPTkRhdGEBDAAAAGX/ggFDPFNlcmlhbGl6YWJsZU1hcD48c2NvcmU+Mjc8L3Njb3JlPjxiaW8+dGV4dDwvYmlvPjwvU2VyaWFsaXphYmxlTWFwPgEbeyJiaW8iOiJ0ZXh0Iiwic2NvcmUiOiIyNyJ9AA=="

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
