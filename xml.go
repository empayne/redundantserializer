package redundantserializer

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
	// Parses entities in the XML string
	expandedXMLString, err := expandXMLString(XMLData)
	if err != nil {
		return nil, err
	}

	// After entity parsing, convert the XML string back to a SerializableMap
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
	// OWASP Top 10 2017 #4: XML External Entities (XXE)
	// We deserialize insecurely (see 'deserialize' in main.go), so the XML
	// section of our redundantStructure can be replaced with arbitrary XML. Our
	// XML parser has external entity parsing enabled, so the attacker can
	// access filesystem contents. For example, to access the machine's
	// /etc/passwd file, we would use a payload like so:
	// <!DOCTYPE SerializableMap [ <!ELEMENT SerializableMap ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><SerializableMap><bio>&xxe;</bio></SerializableMap>
	//
	// This XXE example is a bit artificial. Golang's 'encoding/xml' package
	// doesn't appear to parse XML entities when Unmarshalling, so I'm using the
	// lestrrat-go/libxml2 interface. See: stackoverflow.com/questions/28662417
	//
	// The 'parser.XMLParseNoEnt' parameter should not be enabled here, as this
	// library does not use XML's entity / DTD features.

	doc, err := libxml2.ParseString(xmlString, parser.XMLParseNoEnt)
	defer doc.Free()
	if err != nil {
		return nil, err
	}

	xmlStr := doc.Dump(false)
	return &xmlStr, nil
}
