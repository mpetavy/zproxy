package main

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"github.com/mpetavy/common"
	"io"
	"net"
	"strings"
	"time"
)

// https://en.wikipedia.org/wiki/SOCKS
// Socks4: curl -v -x socks4://localhost:3128 http://www.google.de
// Socks4a: curl -v -x socks4://localhost:3128 http://www.google.de
// dig @localhost -p 1053 test.service

const (
	SOCKS4 = 4
	SOCKS5 = 5

	MODE_TCP_STREAM = 1
	MODE_TCP_BIND   = 2

	REQUEST_GRANTED  = 0x5A
	REQUEST_REJECTED = 0x5B
)

type SocksProxy struct {
	Hostname string
	Port     int
}

var (
	socksPort = flag.String("s", ":1080", "Socks 'address:port' or only ':port'")
	dnsPort   = flag.String("d", ":53", "DNS 'address:port' or only ':port'")
	timeout   = flag.Int("t", 3000, "read timeout")
	records   common.MultiValueFlag

	server    *common.NetworkServer
	dnsServer *dns.Server
)

func init() {
	common.Init(false, "1.0.0", "", "", "2018", "tcpproxy", "mpetavy", fmt.Sprintf("https://github.com/mpetavy/%s", common.Title()), common.APACHE, nil, start, stop, nil, 0)

	flag.Var(&records, "r", "Static record lookups")
}

func NewSocksProxy(conn net.Conn) (*SocksProxy, error) {
	common.DebugFunc()

	hostname, port, err := proxyHandshake(conn)
	if common.WarnError(err) {
		common.Debug("socksproxy: reply rejected")

		common.Error(proxyReply(conn, REQUEST_REJECTED, 0, nil))

		return nil, err
	}

	addrs, err := net.LookupIP(hostname)
	if common.WarnError(err) {
		common.Debug("socksproxy: reply rejected")

		common.Error(proxyReply(conn, REQUEST_REJECTED, 0, nil))

		return nil, err
	}

	var ip net.IP

	for _, tempIp := range addrs {
		if tempIp.To4() != nil {
			ip = tempIp.To4()
		}
	}

	if ip == nil {
		err = fmt.Errorf("cannot find IP4 address")

		if common.WarnError(err) {
			common.Debug("socksproxy: reply rejected")

			common.Error(proxyReply(conn, REQUEST_REJECTED, 0, nil))

			return nil, err
		}
	}

	common.Debug("socksproxy: reply granted")

	common.Error(proxyReply(conn, REQUEST_GRANTED, port, ip))

	sp := &SocksProxy{
		Hostname: hostname,
		Port:     port,
	}

	common.Debug("socksproxy: %+v", sp)

	return sp, nil
}

func proxyReply(conn net.Conn, code int, port int, ip []byte) error {
	buf := make([]byte, 8)

	buf[1] = byte(code)
	buf[2] = byte(port & 0xff00)
	buf[3] = byte(port & 0x00ff)
	if ip != nil {
		for i := 0; i < 4; i++ {
			buf[4+i] = ip[i]
		}
	}

	_, err := conn.Write(buf)

	return err
}

func readDnsName(reader io.Reader) ([]byte, error) {
	var err error

	buf := bytes.Buffer{}
	oneByte := make([]byte, 1)

	for {
		_, err = io.ReadFull(reader, oneByte)
		if common.Error(err) {
			return nil, err
		}

		if oneByte[0] == 0 {
			break
		}

		buf.Write(oneByte)
	}

	return buf.Bytes(), nil
}

func proxyHandshake(conn net.Conn) (string, int, error) {
	reader := common.NewTimeoutReader(conn, common.MillisecondToDuration(*timeout), true)

	defer func() {
		common.Error(conn.SetDeadline(time.Time{}))
	}()

	buf := make([]byte, 1)

	_, err := reader.Read(buf)
	if common.Error(err) {
		return "", 0, err
	}

	if buf[0] != SOCKS4 && buf[0] != SOCKS5 {
		return "", 0, fmt.Errorf("unknown SOCKS connection: %d", buf[0])
	}

	socksVersion := buf[0]

	common.Debug("Request SOCKS connection: %d", socksVersion)

	if socksVersion != SOCKS4 {
		return "", 0, fmt.Errorf("unsupported SOCKS version: %d", socksVersion)
	}

	_, err = io.ReadFull(reader, buf)
	if common.Error(err) {
		return "", 0, err
	}

	mode := buf[0]
	if mode != MODE_TCP_STREAM && mode != MODE_TCP_BIND {
		return "", 0, fmt.Errorf("unknown SOCKS mode: %d", buf[0])
	}

	common.Debug("Request SOCKS mode : %d", mode)

	buf = make([]byte, 2)
	_, err = io.ReadFull(reader, buf)
	if common.Error(err) {
		return "", 0, err
	}

	port := int(int(buf[0])*256) + int(buf[1])

	buf = make([]byte, 4)

	_, err = io.ReadFull(reader, buf)
	if common.Error(err) {
		return "", 0, err
	}

	var hostname string

	if buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[3] != 0 {
		common.Debug("Request SOCKS protocol: 4a")

		// socks4a

		// user
		buf, err = readDnsName(reader)
		if common.Error(err) {
			return "", 0, err
		}

		// domain
		buf, err = readDnsName(reader)
		if common.Error(err) {
			return "", 0, err
		}

		hostname = string(buf)
	} else {
		common.Debug("Request SOCKS protocol: 4")

		// socks4

		hostname = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])

		_, err = readDnsName(reader)
		if common.Error(err) {
			return "", 0, err
		}
	}

	return hostname, port, nil
}

func handleProxyClient(client *common.NetworkConnection) {
	defer func() {
		common.Debug("Client disconnected: %v\n", client.Socket)
		common.Error(client.Close())
	}()

	common.Debug("Client connected: %v\n", client.Socket)

	proxy, err := NewSocksProxy(client.Socket)
	if common.Error(err) {
		return
	}

	remote, err := net.Dial("tcp", fmt.Sprintf("%s:%d", proxy.Hostname, proxy.Port))
	if err != nil {
		return
	}
	defer func() {
		common.Error(remote.Close())
	}()

	common.DataTransfer("proxyclient", client, "destination", remote)
}

func staticRecords(name string) string {
	for _, l := range records {
		splits := strings.Split(l, ":")

		for i := 0; i < len(splits); i++ {
			if len(splits) == 2 {
				host := strings.TrimSpace(splits[0])
				ip := strings.TrimSpace(splits[1])

				if host == name {
					return ip
				}
			}
		}
	}

	return ""
}

func parseDnsQuery(m *dns.Msg) {
	for _, q := range m.Question {
		switch q.Qtype {
		case dns.TypeA:
			common.Debug("Query for %s\n", q.Name)
			ip := staticRecords(q.Name)
			if ip == "" {
				ips, err := net.LookupIP(q.Name)
				if err == nil {
					ip = ips[0].String()
				}
			}
			if ip != "" {
				rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ip))
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
		}
	}
}

func handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		parseDnsQuery(m)
	}

	common.Error(w.WriteMsg(m))
}

func createProxyServer() error {
	common.DebugFunc()

	var err error

	server, err = common.NewNetworkServer(*socksPort, nil)
	if common.Error(err) {
		return err
	}

	err = server.Start()
	if common.Error(err) {
		return err
	}

	go func() {
		defer common.UnregisterGoRoutine(common.RegisterGoRoutine())

		for common.AppLifecycle().IsSet() {
			common.Debug("Wait on client connection...")

			client, err := server.Connect()
			if common.Error(err) {
				return
			}

			go handleProxyClient(client)
		}
	}()

	return nil
}

func createDnsServer() error {
	common.DebugFunc()

	dns.HandleFunc("service.", handleDnsRequest)

	dnsServer = &dns.Server{Addr: fmt.Sprintf("%s", *dnsPort), Net: "udp"}
	err := dnsServer.ListenAndServe()
	if common.Error(err) {
		return err
	}

	return nil
}

func start() error {
	var errProxy error
	var errDns error

	go func() {
		errProxy = createProxyServer()
	}()

	go func() {
		errDns = createDnsServer()
	}()

	time.Sleep(common.MillisecondToDuration(*common.FlagServiceStartTimeout))

	if common.Error(errProxy) {
		return errProxy
	}

	if common.Error(errDns) {
		return errDns
	}

	common.Info("Proxy server listening: %s\n", *socksPort)
	common.Info("DNS server listening: %s\n", *dnsPort)

	return nil
}

func stop() error {
	err := server.Stop()
	if common.Error(err) {
		return err
	}

	return nil
}

func main() {
	defer common.Done()

	common.Run([]string{"s"})
}
