package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var allowedExtensions = []string{"exe", "zip", "rar", "bat", "cmd", "jar", "ps1", "jpg", "jpeg", "gif", "png", "bmp", "txt", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx"}

func proxyHandler(packet gopacket.Packet, client *http.Client) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	_, _ = tcpLayer.(*layers.TCP)

	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		return
	}
	payload := appLayer.Payload()
	request, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(payload)))
	if err != nil {
		fmt.Println("[!] Error reading request:", err)
		return
	}

	request.URL.Scheme = "http"
	request.URL.Host = request.Host
	request.RequestURI = ""

	fmt.Println("[*] Received request:")
	fmt.Printf("[+] Method: %s\n", request.Method)
	fmt.Printf("[+] URL: %s\n", request.URL.String())
	for name, values := range request.Header {
		for _, value := range values {
			fmt.Printf("[+] %s: %s\n", name, value)
		}
	}

	resp, err := client.Do(request)
	if err != nil {
		fmt.Println("[!] Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	handleResponse(packet, resp)
}

func handleResponse(packet gopacket.Packet, resp *http.Response) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	_, _ = tcpLayer.(*layers.TCP)

	fmt.Println("[*] Received response:")
	fmt.Println("[+] Status:", resp.Status)
	for name, values := range resp.Header {
		for _, value := range values {
			fmt.Printf("[+] %s: %s\n", name, value)
		}
	}

	contentType := resp.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "text/html") {
		return
	}
	urlPath, err := url.PathUnescape(resp.Request.URL.Path)
	if err != nil {
		fmt.Println("[!] Error decoding URL path:", err)
		return
	}
	fileName := filepath.Base(urlPath)
	fileExt := strings.ToLower(filepath.Ext(fileName))
	if fileExt != "" && fileExt[1:] != "" && contains(allowedExtensions, fileExt[1:]) {
		content, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("[!] Error reading response body:", err)
			return
		}
		saveFileContent(content, fileName)
	} else {
		fmt.Println("[*] Ignoring file:", fileName)
	}
}

func contains(slice []string, s string) bool {
	for _, elem := range slice {
		if elem == s {
			return true
		}
	}
	return false
}

func saveFileContent(content []byte, fileName string) {
	err := ioutil.WriteFile(fileName, content, 0644)
	if err != nil {
		fmt.Println("[!] Error saving file:", err)
	} else {
		fmt.Println("[*] File saved:", fileName)
	}
}

func main() {
	ifaceName := "eth0" // Replace with the name of your network interface
	iface, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		fmt.Println("[!] Error opening network interface:", err)
		os.Exit(1)
	}
	defer iface.Close()

	filter := "tcp port 80"
	err = iface.SetBPFFilter(filter)
	if err != nil {
		fmt.Println("[!] Error setting BPF filter:", err)
		os.Exit(1)
	}

	packetSource := gopacket.NewPacketSource(iface, iface.LinkType())

	client := &http.Client{
		Transport: &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				conn, err := net.Dial(network, addr)
				if err != nil {
					return nil, err
				}
				return conn, nil
			},
		},
	}

	fmt.Println("[*] Starting packet capture...")
	for packet := range packetSource.Packets() {
			proxyHandler(packet, client)
	}
}
