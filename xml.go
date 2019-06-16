package main

import (
	"encoding/xml"
	"io"

	"github.com/lestrrat-go/libxml2"
	"github.com/lestrrat-go/libxml2/parser"
)

// Used by MarshalXML and UnmarshalXML
type xmlMapEntry struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
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
	xmlString = `<!DOCTYPE SerializableMap [ <!ELEMENT SerializableMap ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><SerializableMap><bio>&xxe;</bio></SerializableMap>`

	doc, err := libxml2.ParseString(xmlString, parser.XMLParseNoEnt)
	defer doc.Free()
	if err != nil {
		return nil, err
	}

	xmlStr := doc.Dump(false)
	return &xmlStr, nil
}
