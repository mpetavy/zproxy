package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/mpetavy/common"
	"io"
	"net"
	"time"
)

// https://en.wikipedia.org/wiki/SOCKS
// Socks4: curl -v -x socks4://localhost:3128 http://www.google.de
// Socks4a: curl -v -x socks4a://localhost:3128 http://www.google.de
// dig @localhost -p 1053 test.service

const (
	DNS_QUERY = 1
	SOCKS4    = 4
	SOCKS5    = 5

	MODE_TCP_STREAM = 1

	SOCKS4_REQUEST_GRANTED  = 0x5A
	SOCKS4_REQUEST_REJECTED = 0x5B

	SOCKS5_REQUEST_GRANTED  = 0x0
	SOCKS5_REQUEST_REJECTED = 0x5
)

var (
	serverAddress = flag.String("s", ":1080", "is server (standalone,proxy bridge)")
	clientAddress = flag.String("c", "", "is client (proxy bridge)")
	timeout       = flag.Int("t", 3000, "read timeout")
	useTls        = flag.Bool("tls", true, "use TLS encryption")

	server    *common.NetworkServer
	tlsConfig *tls.Config
)

func init() {
	common.Init(false, "1.0.0", "", "", "2018", "tcpproxy", "mpetavy", fmt.Sprintf("https://github.com/mpetavy/%s", common.Title()), common.APACHE, nil, start, stop, nil, 0)
}

func NewSocksProxy(conn net.Conn) (string, int, error) {
	common.DebugFunc()

	hostname, port, err := proxyHandshake(conn)
	if common.Error(err) {
		return "", 0, err
	}

	return hostname, port, nil
}

func socks4ProxyReply(conn net.Conn, code int, port int, ip []byte) error {
	buf := make([]byte, 8)

	buf[1] = byte(code)
	buf[2] = byte(port & 0xff00)
	buf[3] = byte(port & 0x00ff)
	if ip != nil {
		for i := 0; i < 4; i++ {
			buf[4+i] = ip[i]
		}
	}

	return writeBytes(conn, buf)
}

func writeBytes(writer io.Writer, buf []byte) error {
	n, err := writer.Write(buf)
	if common.Error(err) {
		return err
	}
	if n != len(buf) {
		return fmt.Errorf("not all bytes written. expected: %d actual: %d", len(buf), n)
	}

	return nil
}

func readBytes(reader io.Reader, length int) ([]byte, error) {
	buf := make([]byte, length)
	n, err := io.ReadFull(reader, buf)
	if common.Error(err) {
		return nil, err
	}
	if n != len(buf) {
		return nil, fmt.Errorf("not all bytes written. expected: %d actual: %d", len(buf), n)
	}

	return buf, nil
}

func readTill0(reader io.Reader) ([]byte, error) {
	buf := bytes.Buffer{}

	for {
		oneByte, err := readBytes(reader, 1)
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

	// read socks version

	buf, err := readBytes(reader, 1)
	if common.Error(err) {
		return "", 0, err
	}

	if buf[0] != DNS_QUERY && buf[0] != SOCKS4 && buf[0] != SOCKS5 {
		return "", 0, fmt.Errorf("Unknown SOCKS version requested: %d", buf[0])
	}

	socksVersion := buf[0]

	common.Debug("Requested SOCKS connection: %d", socksVersion)

	var hostname string
	var port int

	if socksVersion == SOCKS5 {
		buf, err = readBytes(reader, 1)
		if common.Error(err) {
			return "", 0, err
		}

		lenAuthMethods := buf[0]
		buf, err = readBytes(reader, int(lenAuthMethods))
		if common.Error(err) {
			return "", 0, err
		}

		hasNoAuth := false
		for _, auth := range buf {
			hasNoAuth = auth == 0
			if hasNoAuth {
				break
			}
		}

		answer := byte(0)
		if !hasNoAuth {
			answer = 255
		}

		buf = []byte{SOCKS5, answer}
		err = writeBytes(conn, buf)
		if common.Error(err) {
			return "", 0, err
		}

		if !hasNoAuth {
			return "", 0, fmt.Errorf("client does not support NoAuth")
		}

		buf, err = readBytes(reader, 2)
		if common.Error(err) {
			return "", 0, err
		}

		if buf[0] != SOCKS5 {
			return "", 0, fmt.Errorf("Expected SOCKS 5 version failed: %d", buf[0])
		}

		mode := buf[1]
		if mode != MODE_TCP_STREAM {
			return "", 0, fmt.Errorf("Unknown SOCKS mode: %d", buf[0])
		}

		common.Debug("Requested SOCKS mode : %d", mode)

		buf, err = readBytes(reader, 2)
		if common.Error(err) {
			return "", 0, err
		}

		if buf[0] != 0 {
			return "", 0, fmt.Errorf("Expected 0 byte failed: %d", buf[0])
		}

		switch buf[1] {
		case 1: // IPv4
			buf, err = readBytes(reader, 4)
			if common.Error(err) {
				return "", 0, err
			}

			hostname = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
		case 3: // Domainname
			buf, err = readBytes(reader, 1)
			if common.Error(err) {
				return "", 0, err
			}

			lenDomainName := buf[0]
			buf, err = readBytes(reader, int(lenDomainName))
			if common.Error(err) {
				return "", 0, err
			}

			hostname = string(buf)
		case 4: // IPv6
			buf, err = readBytes(reader, 16)
			if common.Error(err) {
				return "", 0, err
			}

			hexValues := hex.EncodeToString(buf)

			for i := 0; i < len(hexValues); i += 4 {
				if i > 0 {
					hostname = hostname + ":"
				}

				hostname = hostname + hexValues[i:i+4]
			}

			hostname = "[" + hostname + "]"
		}

		buf, err = readBytes(reader, 2)
		if common.Error(err) {
			return "", 0, err
		}

		port = int(int(buf[0])*256) + int(buf[1])

		var b bytes.Buffer

		b.WriteByte(SOCKS5)
		b.WriteByte(0)
		b.WriteByte(0)
		b.WriteByte(3)
		b.WriteByte(byte(len(hostname)))
		b.WriteString(hostname)
		b.Write(buf)

		err = writeBytes(conn, b.Bytes())
		if common.Error(err) {
			return "", 0, err
		}
	} else {
		buf, err = readBytes(reader, 1)
		if common.Error(err) {
			return "", 0, err
		}

		mode := buf[0]
		if mode != MODE_TCP_STREAM {
			return "", 0, fmt.Errorf("unknown SOCKS mode: %d", buf[0])
		}

		common.Debug("Request SOCKS mode : %d", mode)

		// read port

		buf, err = readBytes(reader, 2)
		if common.Error(err) {
			return "", 0, err
		}

		port = int(int(buf[0])*256) + int(buf[1])

		buf, err = readBytes(reader, 4)
		if common.Error(err) {
			return "", 0, err
		}

		if buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[3] != 0 {
			common.Debug("Request SOCKS protocol: 4a")

			// socks4a

			// user
			buf, err = readTill0(reader)
			if common.Error(err) {
				return "", 0, err
			}

			// domain
			buf, err = readTill0(reader)
			if common.Error(err) {
				return "", 0, err
			}

			hostname = string(buf)
		} else {
			common.Debug("Request SOCKS protocol: 4")

			// socks4

			hostname = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])

			_, err = readTill0(reader)
			if common.Error(err) {
				return "", 0, err
			}
		}
	}

	return hostname, port, nil
}

func createProxyClient(client *common.NetworkConnection) {
	defer func() {
		common.Debug("Client disconnected: %v\n", client.Socket)
		common.Error(client.Close())
	}()

	common.Debug("Client connected: %v\n", client.Socket)

	hostname, port, err := NewSocksProxy(client.Socket)
	if common.Error(err) {
		return
	}

	common.Debug("Connect to: %s:%d", hostname, port)

	ipbytes := make([]byte, 4)

	remote, err := common.NewNetworkClient(fmt.Sprintf("%s:%d", hostname, port), nil)
	if common.Error(err) {
		socks4ProxyReply(client.Socket, SOCKS4_REQUEST_REJECTED, 0, ipbytes)

		return
	}

	conn, err := remote.Connect()
	if common.Error(err) {
		socks4ProxyReply(client.Socket, SOCKS4_REQUEST_REJECTED, 0, ipbytes)

		return
	}

	socks4ProxyReply(client.Socket, SOCKS4_REQUEST_GRANTED, 0, ipbytes)

	defer func() {
		common.Error(conn.Close())
	}()

	ctx, cancel := context.WithCancel(context.Background())

	common.DataTransfer(ctx, cancel, "proxyclient", client, fmt.Sprintf("%s:%d", hostname, port), conn)
}

func createProxyServer() error {
	common.DebugFunc()

	var err error

	server, err = common.NewNetworkServer(*serverAddress, nil)
	if common.Error(err) {
		return err
	}

	err = server.Start()
	if common.Error(err) {
		return err
	}

	go func() {
		defer common.UnregisterGoRoutine(common.RegisterGoRoutine(1))

		for common.AppLifecycle().IsSet() {
			common.Debug("Wait on client connection...")

			client, err := server.Connect()
			if common.Error(err) {
				continue
			}

			go createProxyClient(client)
		}
	}()

	return nil
}

func start() error {
	var errProxy error

	var err error

	tlsConfig, err = common.NewTlsConfigFromFlags()
	if common.Error(err) {
		return err
	}

	go func() {
		errProxy = createProxyServer()
	}()

	time.Sleep(common.MillisecondToDuration(*common.FlagServiceStartTimeout))

	if common.Error(errProxy) {
		return errProxy
	}

	common.Info("Proxy server listening: %s\n", *serverAddress)

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

	common.Run([]string{"c|s"})
}
