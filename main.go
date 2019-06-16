package main

import (
	"encoding/xml"
	"fmt"
	"io"
)

type redundantStructure struct {
	XMLData  []byte
	JSONData []byte
}

type xmlMapEntry struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

// SerializableMap is used to define map[string]string <-> XML (un)marshalling,
// as Golang's 'encoding/xml' doesn't natively support this.
type SerializableMap map[string]string

func main() {
	// type Foo struct {
	// 	a   string
	// 	bio string
	// }
	// testStruct := Foo{a: "<!ELEMENT bio ANY ><!ENTITY e SYSTEM 'file:///etc/passwd' >", bio: "&e;"}
	// testMSS := map[string]string{"a": testStruct.a, "bio": testStruct.bio}

	// serialized, err := serialize(testMSS)
	// if err != nil {
	// 	fmt.Println(err)
	// } else {
	// 	fmt.Println(*serialized)
	// }

	// //toDeserialize := "Of+BAwEBEnJlZHVuZGFudFN0cnVjdHVyZQH/ggABAgEHWE1MRGF0YQEKAAEISlNPTkRhdGEBCgAAAGr/ggFJPFNlcmlhbGl6YWJsZU1hcD4KICA8c2NvcmU+MTwvc2NvcmU+CiAgPGJpbz50ZXh0PC9iaW8+CjwvU2VyaWFsaXphYmxlTWFwPgEaeyJiaW8iOiJ0ZXh0Iiwic2NvcmUiOiIxIn0A"
	//toDeserialize := "Of+BAwEBEnJlZHVuZGFudFN0cnVjdHVyZQH/ggABAgEHWE1MRGF0YQEKAAEISlNPTkRhdGEBCgAAAP/7/4IB/4s8U2VyaWFsaXphYmxlTWFwPjxhPiZsdDshRUxFTUVOVCBiaW8gQU5ZICZndDsmbHQ7IUVOVElUWSBlIFNZU1RFTSAmIzM5O2ZpbGU6Ly8vZXRjL3Bhc3N3ZCYjMzk7ICZndDs8L2E+PGJpbz4mYW1wO2U7PC9iaW8+PC9TZXJpYWxpemFibGVNYXA+AWh7ImEiOiJcdTAwM2MhRUxFTUVOVCBiaW8gQU5ZIFx1MDAzZVx1MDAzYyFFTlRJVFkgZSBTWVNURU0gJ2ZpbGU6Ly8vZXRjL3Bhc3N3ZCcgXHUwMDNlIiwiYmlvIjoiXHUwMDI2ZTsifQA="
	deserialized, err := deserialize()
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(deserialized)
	}
}

// func serialize(in SerializableMap) (*string, error) {
// 	xmlData, err := xml.Marshal(in)
// 	if err != nil {
// 		return nil, err
// 	}

// 	jsonData, err := json.Marshal(in)
// 	if err != nil {
// 		return nil, err
// 	}

// 	toSerialize := redundantStructure{xmlData, jsonData}
// 	return toBase64(toSerialize)
// }

func deserialize() (SerializableMap, error) {
	// decoded, err := fromBase64(in)
	// if err != nil {
	// 	return nil, err
	// }

	// fmt.Println(decoded)

	var xmlDeserialized SerializableMap
	byteData := []byte{60, 83, 101, 114, 105, 97, 108, 105, 122, 97, 98, 108, 101, 77, 97, 112, 62, 60, 115, 99, 111, 114, 101, 62, 49, 60, 47, 115, 99, 111, 114, 101, 62, 60, 98, 105, 111, 62, 102, 117, 99, 107, 60, 47, 98, 105, 111, 62, 60, 47, 83, 101, 114, 105, 97, 108, 105, 122, 97, 98, 108, 101, 77, 97, 112, 62}

	err := xml.Unmarshal( /*decoded.XMLData*/ byteData, &xmlDeserialized)
	if err != nil {
		return nil, err
	}
	fmt.Println(xmlDeserialized)

	return nil, nil
}

// MarshalXML asda
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

// UnmarshalXML asda
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

// // MarshalXML maps our SerializableMap to XML data.
// // Inspired by https://blog.csdn.net/tangtong1/article/details/80418286
// func (m SerializableMap) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
// 	if len(m) == 0 {
// 		return nil
// 	}

// 	err := e.EncodeToken(start)
// 	if err != nil {
// 		return err
// 	}

// 	for k, v := range m {
// 		e.Encode(xmlMapEntry{XMLName: xml.Name{Local: k}, Value: v})
// 	}

// 	return e.EncodeToken(start.End())
// }

// // UnmarshalXML maps our XML data back to a SerializableMap.
// // Inspired by https://blog.csdn.net/tangtong1/article/details/80418286
// func (m *SerializableMap) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
// 	d.Strict = false
// 	//d.Entity = xml.HTMLEntity
// 	//d.Entity["xxe"] = "<!ENTITY e SYSTEM 'file:///etc/passwd' >"
// 	//d.CharsetReader = charset.NewReaderLabel
// 	*m = SerializableMap{}
// 	for {
// 		var e xmlMapEntry

// 		err := d.Decode(&e)
// 		if err == io.EOF {
// 			break
// 		} else if err != nil {
// 			return err
// 		}

// 		(*m)[e.XMLName.Local] = e.Value
// 	}
// 	return nil
// }

// func (m *SerializableMap) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
// 	*m = StringMap{}
// 	for {
// 		var e xmlMapEntry

// 		err := d.Decode(&e)
// 		if err == io.EOF {
// 			break
// 		} else if err != nil {
// 			return err
// 		}

// 		(*m)[e.XMLName.Local] = e.Value
// 	}
// 	return nil
// }

// // Inspired by https://stackoverflow.com/questions/28020070
// func toBase64(m redundantStructure) (*string, error) {
// 	b := bytes.Buffer{}
// 	e := gob.NewEncoder(&b)

// 	// TODO: potential optimization by not calling gob.Register every time
// 	gob.Register(redundantStructure{})
// 	err := e.Encode(m)
// 	if err != nil {
// 		return nil, err
// 	}

// 	encoded := base64.StdEncoding.EncodeToString(b.Bytes())
// 	return &encoded, nil
// }

// // Inspired by https://stackoverflow.com/questions/28020070
// func fromBase64(str string) (*redundantStructure, error) {
// 	m := redundantStructure{}
// 	by, err := base64.StdEncoding.DecodeString(str)
// 	if err != nil {
// 		return nil, err
// 	}
// 	b := bytes.Buffer{}
// 	b.Write(by)
// 	d := gob.NewDecoder(&b)
// 	err = d.Decode(&m)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return &m, nil
// }
