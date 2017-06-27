// Copyright 2017 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package common

import (
	"fmt"
	"unsafe"

	"github.com/intel-go/yanff/packet"
)

type Packetdata struct {
	F1, F2 uint64
}

func CheckPacketChecksums(p *packet.Packet) bool {
	status := false

	if p.Ether.EtherType == packet.SwapBytesUint16(packet.IPV4Number) {
		l3status := true
		if p.IPv4.HdrChecksum != CalculateIPv4Checksum(p) {
			println("IPv4 checksum mismatch")
			l3status = false
		}

		if p.IPv4.NextProtoID == packet.UDPNumber {
			csum := CalculateIPv4UDPChecksum(p)
			if p.UDP.DgramCksum != csum {
				println("IPv4 UDP datagram checksum mismatch", p.UDP.DgramCksum, "should be", csum)
			} else {
				status = l3status
			}
		} else if p.IPv4.NextProtoID == packet.TCPNumber {
			csum := CalculateIPv4TCPChecksum(p)
			if p.TCP.Cksum != csum {
				println("IPv4 TCP checksum mismatch", p.TCP.Cksum, "should be", csum)
			} else {
				status = l3status
			}
		} else {
			println("Unknown IPv4 protocol number", p.IPv4.NextProtoID)
		}
	} else if p.Ether.EtherType == packet.SwapBytesUint16(packet.IPV6Number) {
		if p.IPv6.Proto == packet.UDPNumber {
			csum := CalculateIPv6UDPChecksum(p)
			if p.UDP.DgramCksum != csum {
				println("IPv6 UDP datagram checksum mismatch:", p.UDP.DgramCksum, "should be", csum)
			} else {
				status = true
			}
		} else if p.IPv6.Proto == packet.TCPNumber {
			csum := CalculateIPv6TCPChecksum(p)
			if p.TCP.Cksum != csum {
				println("IPv6 TCP datagram checksum mismatch", p.TCP.Cksum, "should be", csum)
			} else {
				status = true
			}
		} else {
			println("Unknown IPv6 protocol number", p.IPv6.Proto)
		}
	} else {
		println("Unknown packet EtherType", p.Ether.EtherType)
	}

	return status
}

func CalculateIPv4Checksum(p *packet.Packet) uint16 {
	var sum uint32
	hdr := p.IPv4

	sum = uint32(hdr.VersionIhl << 8) + uint32(hdr.TypeOfService) +
		uint32(packet.SwapBytesUint16(hdr.TotalLength)) +
		uint32(packet.SwapBytesUint16(hdr.PacketID)) +
		uint32(packet.SwapBytesUint16(hdr.FragmentOffset)) +
		uint32(hdr.TimeToLive << 8) + uint32(hdr.NextProtoID) +
		uint32(packet.SwapBytesUint16(uint16(hdr.SrcAddr >> 16))) +
        uint32(packet.SwapBytesUint16(uint16(hdr.SrcAddr))) +
		uint32(packet.SwapBytesUint16(uint16(hdr.DstAddr >> 16))) +
		uint32(packet.SwapBytesUint16(uint16(hdr.DstAddr)))

	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return uint16(^sum)
}

func CalculateIPv4UDPChecksum(p *packet.Packet) uint16 {
	var sum uint32 = 0
	hdr := p.IPv4
	uptr := uintptr(p.Data)
	uptr -= packet.UDPLen
	dataLength := packet.SwapBytesUint16(hdr.TotalLength) - packet.IPv4MinLen

	for i := uintptr(0); i < uintptr(dataLength - packet.UDPLen); i += 2 {
		sum += uint32(packet.SwapBytesUint16(*(*uint16)(unsafe.Pointer(uptr + i))))
		fmt.Printf("data = 0x%04x, sum = 0x%x\n", uint32(packet.SwapBytesUint16(*(*uint16)(unsafe.Pointer(uptr + i)))), sum)
	}

	sum += uint32(packet.SwapBytesUint16(uint16(hdr.SrcAddr >> 16))) +
		uint32(packet.SwapBytesUint16(uint16(hdr.SrcAddr))) +
		uint32(packet.SwapBytesUint16(uint16(hdr.DstAddr >> 16))) +
		uint32(packet.SwapBytesUint16(uint16(hdr.DstAddr))) +
		uint32(hdr.NextProtoID) +
		uint32(dataLength - packet.UDPLen)

	fmt.Printf("0x%04x + 0x%04x + 0x%04x + 0x%04x + 0x%04x + 0x%04x = %x\n",
		uint32(packet.SwapBytesUint16(uint16(hdr.SrcAddr >> 16))),
		uint32(packet.SwapBytesUint16(uint16(hdr.SrcAddr))),
		uint32(packet.SwapBytesUint16(uint16(hdr.DstAddr >> 16))),
		uint32(packet.SwapBytesUint16(uint16(hdr.DstAddr))),
		uint32(hdr.NextProtoID),
		uint32(dataLength - packet.UDPLen),
		sum)

	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}

	return uint16(^sum)
}

func CalculateIPv4TCPChecksum(p *packet.Packet) uint16 {
	return 0
}

func CalculateIPv6UDPChecksum(p *packet.Packet) uint16 {
	return 0
}

func CalculateIPv6TCPChecksum(p *packet.Packet) uint16 {
	return 0
}

func CalculateChecksum(p *packet.Packet) {
	if p.Ether.EtherType == packet.SwapBytesUint16(packet.IPV4Number) {
		p.IPv4.HdrChecksum = CalculateIPv4Checksum(p)

		if p.IPv4.NextProtoID == packet.UDPNumber {
			p.UDP.DgramCksum = CalculateIPv4UDPChecksum(p)
		} else if p.IPv4.NextProtoID == packet.TCPNumber {
			p.TCP.Cksum = CalculateIPv4TCPChecksum(p)
		} else {
			println("Unknown IPv4 protocol number", p.IPv4.NextProtoID)
			println("TEST FAILED")
		}
	} else if p.Ether.EtherType == packet.SwapBytesUint16(packet.IPV6Number) {
		if p.IPv6.Proto == packet.UDPNumber {
			p.UDP.DgramCksum = CalculateIPv6UDPChecksum(p)
		} else if p.IPv6.Proto == packet.TCPNumber {
			p.TCP.Cksum = CalculateIPv6TCPChecksum(p)
		} else {
			println("Unknown IPv6 protocol number", p.IPv6.Proto)
			println("TEST FAILED")
		}
	} else {
		println("Unknown packet EtherType", p.Ether.EtherType)
		println("TEST FAILED")
	}
}
