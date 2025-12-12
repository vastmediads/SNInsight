package parser

import (
	"encoding/binary"
	"errors"
)

var (
	ErrNotTLSHandshake  = errors.New("不是 TLS 握手消息")
	ErrNotClientHello   = errors.New("不是 ClientHello")
	ErrPayloadTooShort  = errors.New("payload 太短")
	ErrNoSNIExtension   = errors.New("没有 SNI 扩展")
	ErrInvalidSNIFormat = errors.New("SNI 格式无效")
)

const (
	tlsHandshake    = 0x16
	tlsClientHello  = 0x01
	extensionSNI    = 0x0000
	sniHostNameType = 0x00
)

// ExtractSNI 从 TLS ClientHello payload 中提取 SNI
func ExtractSNI(payload []byte) (string, error) {
	if len(payload) < 6 {
		return "", ErrPayloadTooShort
	}

	// 检查是否为 TLS Handshake
	if payload[0] != tlsHandshake {
		return "", ErrNotTLSHandshake
	}

	// 检查 TLS 版本 (0x0301=TLS1.0, 0x0302=TLS1.1, 0x0303=TLS1.2/1.3)
	// payload[1:3] 是版本，我们不严格检查

	// payload[3:5] 是记录长度
	recordLen := binary.BigEndian.Uint16(payload[3:5])
	if int(recordLen)+5 > len(payload) {
		return "", ErrPayloadTooShort
	}

	// payload[5] 应该是 ClientHello (0x01)
	if payload[5] != tlsClientHello {
		return "", ErrNotClientHello
	}

	// ClientHello 长度在 payload[6:9] (3字节)
	if len(payload) < 9 {
		return "", ErrPayloadTooShort
	}

	// 跳过 ClientHello 头部，找到扩展部分
	// 结构: HandshakeType(1) + Length(3) + Version(2) + Random(32) + SessionID(1+var) + CipherSuites(2+var) + Compression(1+var) + Extensions(2+var)
	pos := 5 + 1 + 3 + 2 + 32 // 到达 SessionID 长度位置

	if pos >= len(payload) {
		return "", ErrPayloadTooShort
	}

	// SessionID
	sessionIDLen := int(payload[pos])
	pos += 1 + sessionIDLen

	if pos+2 > len(payload) {
		return "", ErrPayloadTooShort
	}

	// CipherSuites
	cipherSuitesLen := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2 + cipherSuitesLen

	if pos+1 > len(payload) {
		return "", ErrPayloadTooShort
	}

	// Compression Methods
	compressionLen := int(payload[pos])
	pos += 1 + compressionLen

	if pos+2 > len(payload) {
		return "", ErrPayloadTooShort
	}

	// Extensions 长度
	extensionsLen := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2

	if pos+extensionsLen > len(payload) {
		extensionsLen = len(payload) - pos // 截断情况，尽量解析
	}

	// 遍历扩展找 SNI
	extEnd := pos + extensionsLen
	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(payload[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(payload[pos+2 : pos+4]))
		pos += 4

		if pos+extLen > extEnd {
			break
		}

		if extType == extensionSNI {
			return parseSNIExtension(payload[pos : pos+extLen])
		}

		pos += extLen
	}

	return "", ErrNoSNIExtension
}

// parseSNIExtension 解析 SNI 扩展数据
func parseSNIExtension(data []byte) (string, error) {
	if len(data) < 5 {
		return "", ErrInvalidSNIFormat
	}

	// SNI 列表长度
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if listLen+2 > len(data) {
		listLen = len(data) - 2
	}

	pos := 2
	listEnd := pos + listLen

	for pos+3 <= listEnd {
		nameType := data[pos]
		nameLen := int(binary.BigEndian.Uint16(data[pos+1 : pos+3]))
		pos += 3

		if pos+nameLen > listEnd {
			break
		}

		if nameType == sniHostNameType {
			return string(data[pos : pos+nameLen]), nil
		}

		pos += nameLen
	}

	return "", ErrNoSNIExtension
}

// IsTLSClientHello 快速判断是否为 TLS ClientHello
func IsTLSClientHello(payload []byte) bool {
	if len(payload) < 6 {
		return false
	}
	return payload[0] == tlsHandshake && payload[5] == tlsClientHello
}
