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
	testStruct := Foo{score: "27", bio: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaatext"}
	testMSS := map[string]string{"score": testStruct.score, "bio": testStruct.bio}

	serialized, err := Serialize(testMSS)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(*serialized)
	}

	//this one below has the xxe payload
	//testB64String := "Of+BAwEBEnJlZHVuZGFudFN0cnVjdHVyZQH/ggABAgEHWE1MRGF0YQEMAAEISlNPTkRhdGEBDAAAAP4BFP+CAf+aPCFET0NUWVBFIFNlcmlhbGl6YWJsZU1hcCBbIDwhRUxFTUVOVCBTZXJpYWxpemFibGVNYXAgQU5ZID48IUVOVElUWSB4eGUgU1lTVEVNICJmaWxlOi8vL2V0Yy9wYXNzd2QiID5dPjxTZXJpYWxpemFibGVNYXA+PGJpbz4meHhlOzwvYmlvPjwvU2VyaWFsaXphYmxlTWFwPgFyeyJiaW8iOiJhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWF0ZXh0Iiwic2NvcmUiOiIyNyJ9AA=="

	//this one has a normal payload
	//testB64String := "Of+BAwEBEnJlZHVuZGFudFN0cnVjdHVyZQH/ggABAgEHWE1MRGF0YQEMAAEISlNPTkRhdGEBDAAAAP4BFP+CAf+aPFNlcmlhbGl6YWJsZU1hcD48c2NvcmU+Mjc8L3Njb3JlPjxiaW8+YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhdGV4dDwvYmlvPjwvU2VyaWFsaXphYmxlTWFwPgFyeyJiaW8iOiJhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWF0ZXh0Iiwic2NvcmUiOiIyNyJ9AA=="

	//this one has a score-modified payload
	testB64String := "Of+BAwEBEnJlZHVuZGFudFN0cnVjdHVyZQH/ggABAgEHWE1MRGF0YQEMAAEISlNPTkRhdGEBDAAAAP4BFP+CAf+aPFNlcmlhbGl6YWJsZU1hcD48c2NvcmU+OTk8L3Njb3JlPjxiaW8+YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhdGV4dDwvYmlvPjwvU2VyaWFsaXphYmxlTWFwPgFyeyJiaW8iOiJhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWF0ZXh0Iiwic2NvcmUiOiI5OSJ9AAo="

	deserialized, err := Deserialize(testB64String)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(deserialized)
	}
}

// Serialize produces a binary blob with built-in redundancy. We convert the
// map[string]string into a struct holding the map's data in both JSON and XML
// formats, then gob it / export a base64 string.
func Serialize(in SerializableMap) (*string, error) {
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

// Deserialize takes our binary blob produced by Serialize, checks that the
// map[string]string data produced by both XML and JSON strings match, and then
// returns that map. If the two maps are not equal, we return an error.
func Deserialize(in string) (SerializableMap, error) {
	// OWASP Top 10 2017 #8: Insecure Deserialization
	// We don't check the integrity of the base64 string before deserializing
	// it. If an attacker can reverse-engineer the file format (which is trivial
	// here, they can alter parameters such as their score before re-uploading
	// the binary blob.
	//
	// We should be checking that the blob has not been tampered with via a
	// cryptographic signature.

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

	// Arbitrarily return xmlMap over jsonMap; we already know they're equal
	return xmlMap, nil
}
