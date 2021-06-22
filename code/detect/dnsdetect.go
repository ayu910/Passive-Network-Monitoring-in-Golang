package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var arr map[TXID_query]Reponse_struct

const iterate_time = 10

type TXID_query struct {
	num int
}
type Reponse_struct struct {
	answerIP       [][]string
	last_queryTime time.Time
	queryCount     int
	nAnswer        int
}

func detect(packet gopacket.Packet) {
	var dnsID uint16
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer != nil {
		dns := dnsLayer.(*layers.DNS)
		dnsID = dns.ID
		for _, dnsQuestion := range dns.Questions {
			pktTime := packet.Metadata().Timestamp
			fmt.Println("query :", dnsQuestion.Name)
			if !(dns.ANCount > 0) {
				if _, contains := arr[TXID_query{num: int(dnsID)}]; contains {
					Reponse_struct := arr[TXID_query{num: int(dnsID)}]
					Reponse_struct.queryCount += 1
					arr[TXID_query{num: int(dnsID)}] = Reponse_struct
				} else {
					arr[TXID_query{num: int(dnsID)}] = Reponse_struct{queryCount: 1, nAnswer: 0, last_queryTime: pktTime, answerIP: make([][]string, 0)}
				}
			} else {
				if _, contains := arr[TXID_query{num: int(dnsID)}]; contains {
					Reponse_struct := arr[TXID_query{num: int(dnsID)}]
					Reponse_struct.nAnswer += 1
					list_of_answer_ip := make([]string, 1)
					for _, dnsAnswer := range dns.Answers {
						list_of_answer_ip = append(list_of_answer_ip, dnsAnswer.IP.String())
					}
					Reponse_struct.answerIP = append(Reponse_struct.answerIP, list_of_answer_ip)
					arr[TXID_query{num: int(dnsID)}] = Reponse_struct
					if Reponse_struct.last_queryTime.Sub(pktTime).Seconds() > iterate_time {
						delete(arr, TXID_query{num: int(dnsID)}) //check every 10 secs
					} else if Reponse_struct.nAnswer > Reponse_struct.queryCount {
						question_name := string(dns.Questions[0].Name)
						fmt.Println("Attack Detected....")
						fmt.Println("TXID " + strconv.Itoa(int(dnsID)) + ", Request " + question_name)
						for i := 0; i < len(Reponse_struct.answerIP); i++ {
							fmt.Printf("Answer"+strconv.Itoa(i)+" %v\n", Reponse_struct.answerIP[i])
						}
						arr[TXID_query{num: int(dnsID)}] = Reponse_struct
					}
				}
			}
		}
	}
}
func getIface(value string) string {
	devices, _ := pcap.FindAllDevs()
	n := len(devices)
	var availableDevices = make([]string, n, n)
	valueAvailable := false
	for i, device := range devices {
		availableDevices[i] = device.Name
		if device.Name == value {
			valueAvailable = true
		}
	}
	if value != "" && !valueAvailable {
		fmt.Println("Wrong interfcae. Available interfcaes are", availableDevices)
		os.Exit(1)
	}
	if valueAvailable {
		return value
	} else {
		return availableDevices[0]
	}
}
func main() {
	var expression, fileName, interfcae string
	var handle *pcap.Handle
	var err error
	for i, v := range os.Args {
		if v == "-i" {
			interfcae = os.Args[i+1]
			fmt.Println("interfcae: ", interfcae)
		} else if v == "-r" && interfcae == "" {
			fileName = os.Args[i+1]
			fmt.Println("FileName ", fileName)
		} else if i > 0 && os.Args[i-1] != "-i" && os.Args[i-1] != "-r" {
			expression = os.Args[i]
			expression = "udp and port 53 and " + expression
			fmt.Println("BPF filter: ", expression)
		}
	}
	if expression == "" {
		expression = "udp and port 53"
	}
	err = handle.SetBPFFilter(expression)
	if err != nil {
		log.Fatal(err)
	}
	if fileName != "" {
		handle, err = pcap.OpenOffline(fileName)
	} else {
		var buffer = int32(1600)
		iface := getIface(interfcae)
		handle, err = pcap.OpenLive(iface, buffer, true, 30)
	}
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	arr = make(map[TXID_query]Reponse_struct)
	for packet := range packetSource.Packets() {
		detect(packet)
	}
}
