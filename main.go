package main

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"fmt"
)

type redundantStructure struct {
	XMLString  string
	JSONString string
}

func main() {
	type Foo struct {
		score int
		bio   string
	}
	testStruct := Foo{score: 1, bio: "text"}
	testMSI := map[string]interface{}{"score": testStruct.score, "bio": testStruct.bio}
	serialized := serialize(testMSI)
	fmt.Println(serialized)
}

func serialize(in map[string]interface{}) string {
	jsonString := getJSONString(in)
	xmlString := getXMLString(in)
	toSerialize := redundantStructure{jsonString, xmlString}
	serialized := toGOB64(toSerialize)
	return serialized
}

func getJSONString(in map[string]interface{}) string {
	return "unimplemented json"
}

func getXMLString(in map[string]interface{}) string {
	return "unimplemented xml"
}

// go binary encoder, inspired by https://stackoverflow.com/questions/28020070/
func toGOB64(m redundantStructure) string {
	b := bytes.Buffer{}
	e := gob.NewEncoder(&b)
	// TODO: potential optimization by not calling gob.Register every time
	gob.Register(redundantStructure{})
	err := e.Encode(m)
	if err != nil {
		fmt.Println(`failed gob Encode`, err)
	}
	return base64.StdEncoding.EncodeToString(b.Bytes())
}
