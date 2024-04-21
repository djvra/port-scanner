package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func printUsage() {
	fmt.Println("Usage: go run main.go -ip <IP>")
	fmt.Println("Usage: go run main.go -ip <IP> -port <PORT>")
	fmt.Println("Usage: go run main.go -ip <IP> -port <PORT> [-sS/-sU]")
}

func parsePorts(portStr string) ([]int, error) {
	ports := make([]int, 0)

	// Check if portStr is a range
	if strings.Contains(portStr, "-") {
		parts := strings.Split(portStr, "-")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid port range")
		}

		start, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, err
		}

		end, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, err
		}

		for port := start; port <= end; port++ {
			ports = append(ports, port)
		}
	} else if strings.Contains(portStr, ",") {
		// portStr is a list of ports
		parts := strings.Split(portStr, ",")
		for _, part := range parts {
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, err
			}
			ports = append(ports, port)
		}
	} else {
		// portStr is a single port
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, err
		}
		ports = append(ports, port)
	}

	return ports, nil
}

func getHostname(ip string) string {
	hostnames, err := net.LookupAddr(ip)
	if err != nil {
		return "Could not found hostname for IP address"
	} else {
		return hostnames[0]
	}
}

func getLocalIP() net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Fatal(err)
	}

	var localIP net.IP

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				localIP = ipnet.IP
				break
			}
		}
	}
	return localIP
}

func main() {

	// Define flags
	sS := flag.Bool("sS", false, "SYN scan")
	sU := flag.Bool("sU", false, "UDP scan")
	p := flag.String("p", "", "Port number")
	target_ip := flag.String("ip", "", "IP address")

	// Parse the flags
	flag.Parse()

	// public ip address ???
	/*conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	fmt.Println(localAddr.IP)*/

	// Get the local IP address
	localIP := getLocalIP()
	fmt.Printf("localIP : %s\n", localIP.String())

	// Print the values of the variables
	fmt.Printf("Scanning IP: %s\n", *target_ip)
	fmt.Printf("Ports: %s\n", *p)

	ports, err := parsePorts(*p)
	if err != nil {
		fmt.Println("Invalid port(s).")
		return
	}

	// Perform TCP Connect scan if -sS flag is set or no flags are provided
	if *sS || (!*sS && !*sU) {

		fmt.Printf("Hostname: %s\n", getHostname(*target_ip))

		// Create a semaphore with a maximum of 100 concurrent goroutines
		semaphore := make(chan struct{}, 1000)
		var wg sync.WaitGroup

		for _, port := range ports {
			// Increment the WaitGroup counter
			wg.Add(1)

			// Acquire a semaphore
			semaphore <- struct{}{}

			go func(port int) {
				// Release the semaphore when the goroutine completes
				defer func() {
					<-semaphore
					wg.Done()
				}()

				address := net.JoinHostPort(*target_ip, strconv.Itoa(port))
				conn, err := net.DialTimeout("tcp", address, 1*time.Second)

				if err == nil {
					conn.Close()
					fmt.Printf("Open port found: %d\n", port)
				}
			}(port) // Pass the port as an argument to the goroutine
		}
		// Wait for all goroutines to complete
		wg.Wait()
	} else if *sU {
		// Perform UDP scan if -sU flag is set
		fmt.Println("UDP scan")

		// Iterate over the ports
		for _, port := range ports {
			// Open a live packet capture from the Ethernet device
			handle, err := pcap.OpenLive("wlp3s0", 1600, true, pcap.BlockForever)
			if err != nil {
				panic(err)
			}
			defer handle.Close()

			// Create a new packet
			buffer := gopacket.NewSerializeBuffer()
			options := gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			}

			// Create the IP layer
			ip := &layers.IPv4{
				SrcIP: net.IP{localIP[0], localIP[1], localIP[2], localIP[3]},
				DstIP: net.ParseIP(*target_ip),
			}

			// Create the UDP layer
			udp := &layers.UDP{
				SrcPort: layers.UDPPort(12345),
				DstPort: layers.UDPPort(port), // Use the current port
			}
			udp.SetNetworkLayerForChecksum(ip)

			// Serialize the packet
			err = gopacket.SerializeLayers(buffer, options, ip, udp)
			if err != nil {
				panic(err)
			}

			// Send the packet
			err = handle.WritePacketData(buffer.Bytes())
			if err != nil {
				panic(err)
			}

			// Wait for a response
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			timeout := time.After(2 * time.Second) // Set a timeout for waiting for a response

		loop:
			for {
				select {
				case packet := <-packetSource.Packets():
					// Check if the packet is an ICMP packet
					if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
						icmp, _ := icmpLayer.(*layers.ICMPv4)

						// Check if the ICMP message is a "destination unreachable" message
						if icmp.TypeCode == layers.ICMPv4TypeDestinationUnreachable {
							fmt.Printf("Port %d is closed\n", port)
						} else {
							fmt.Printf("Port %d is open\n", port)
						}
						break loop
					}
				case <-timeout:
					fmt.Printf("Port %d timeout\n", port)
					break loop
				}
			}
		}
	}

}
