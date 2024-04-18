package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"embed"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/mpetavy/common"
	"io"
	"net"
	"os"
)

// https://en.wikipedia.org/wiki/SOCKS
//
// Socks4: curl -v -x socks4://localhost:1080 http://www.google.de
// Socks4a: curl -v -x socks4a://localhost:1080 http://www.google.de
// Socks5: curl -v -x socks5://localhost:1080 http://www.google.de
// Socks5h: curl -v -x socks5h://localhost:1080 http://www.google.de
//
// Socks4: local DNS resolution
// Socks5: local DNS resolution
//
// Socks4a: remote DNS resolution
// Socks5h: remote DNS resolution
//
// https://technik-blog.eu/2023/04/socks5-proxy-server-mit-curl-nutzen/
// https://blog.emacsos.com/use-socks5-proxy-in-curl.html
// https://datatracker.ietf.org/doc/html/rfc1929
//
// Linux
//
// export http_proxy=socks5h://172.23.192.1:1080
// export https_proxy=socks5h://172.23.192.1:1080
// export all_proxy=socks5h://172.23.192.1:1080
//
// export HTTP_PROXY=socks5h://172.23.192.1:1080
// export HTTPS_PROXY=socks5h://172.23.192.1:1080
// export ALL_PROXY=socks5h://172.23.192.1:1080

const (
	SOCKS4 = 4
	SOCKS5 = 5

	MODE_TCP_STREAM = 1

	SOCKS4_REQUEST_GRANTED  = 0x5A
	SOCKS4_REQUEST_REJECTED = 0x5B

	SOCKS5_REQUEST_GRANTED  = 0x0
	SOCKS5_REQUEST_REJECTED = 0x5

	AUTH_NONE              = 0
	AUTH_GSSAPI            = 1
	AUTH_USERNAME_PASSWORD = 2
)

var (
	serverAddress = flag.String("s", ":1080", "is server (standalone,proxy bridge)")
	timeout       = flag.Int("t", 3000, "read timeout")
	username      = flag.String("u", "", "username")
	password      = flag.String("p", "", "password")
	useTls        = flag.Bool("tls", false, "use TLS")

	server *common.NetworkServer
)

//go:embed go.mod
var resources embed.FS

func init() {
	common.Init("", "", "", "", "tcpproxy", "", "", "", &resources, start, stop, nil, 0)
}

func writeBytes(writer io.Writer, buf []byte) error {
	common.DebugFunc()

	timeoutWriter := common.NewTimeoutWriter(writer, true, common.MillisecondToDuration(*timeout))

	n, err := timeoutWriter.Write(buf)
	if common.Error(err) {
		return err
	}
	if n != len(buf) {
		return fmt.Errorf("not all bytes written. expected: %d actual: %d", len(buf), n)
	}

	return nil
}

func readBytes(reader io.Reader, length int) ([]byte, error) {
	common.DebugFunc()

	timeoutReader := common.NewTimeoutReader(reader, true, common.MillisecondToDuration(*timeout))

	buf := make([]byte, length)
	n, err := io.ReadFull(timeoutReader, buf)
	if common.Error(err) {
		return nil, err
	}
	if n != len(buf) {
		return nil, fmt.Errorf("not all bytes written. expected: %d actual: %d", len(buf), n)
	}

	return buf, nil
}

func readTill0(reader io.Reader) ([]byte, error) {
	common.DebugFunc()

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

func handshake(conn net.Conn) (int, string, int, error) {
	common.DebugFunc()

	// read socks version

	buf, err := readBytes(conn, 1)
	if common.Error(err) {
		return 0, "", 0, err
	}

	if buf[0] != SOCKS4 && buf[0] != SOCKS5 {
		return 0, "", 0, fmt.Errorf("Unknown SOCKS version requested: %d", buf[0])
	}

	socksVersion := int(buf[0])

	common.Debug("Requested SOCKS connection: %d", socksVersion)

	var hostname string
	var port int

	if socksVersion == SOCKS5 {
		// read client supported auth methods

		buf, err = readBytes(conn, 1)
		if common.Error(err) {
			return socksVersion, "", 0, err
		}

		lenAuthMethods := buf[0]
		buf, err = readBytes(conn, int(lenAuthMethods))
		if common.Error(err) {
			return socksVersion, "", 0, err
		}

		hasUsernamePassword := false
		hasNoAuth := false

		for _, auth := range buf {
			switch auth {
			case AUTH_NONE:
				hasNoAuth = true
			case AUTH_USERNAME_PASSWORD:
				hasUsernamePassword = true
			}
		}

		if !hasNoAuth && !hasUsernamePassword {
			// send "unsupported auth methods"

			err = writeBytes(conn, []byte{SOCKS5, 255})
			if common.Error(err) {
				return socksVersion, "", 0, err
			}

			return socksVersion, "", 0, fmt.Errorf("client auths not supported: %v", buf)
		}

		// send server choosen auth method

		if hasNoAuth {
			// send "no authentication required" method

			err = writeBytes(conn, []byte{SOCKS5, AUTH_NONE})
			if common.Error(err) {
				return socksVersion, "", 0, err
			}
		}

		if hasUsernamePassword {
			// send "username/password" method

			err = writeBytes(conn, []byte{SOCKS5, AUTH_USERNAME_PASSWORD})
			if common.Error(err) {
				return socksVersion, "", 0, err
			}

			// reads client authentication

			_, err = readBytes(conn, 1)
			if common.Error(err) {
				return socksVersion, "", 0, err
			}

			// read username

			buf, err = readBytes(conn, 1)
			if common.Error(err) {
				return socksVersion, "", 0, err
			}

			len := buf[0]

			buf, err = readBytes(conn, int(len))
			if common.Error(err) {
				return socksVersion, "", 0, err
			}

			clientUsername := string(buf)

			// read password

			len = buf[0]

			buf, err = readBytes(conn, int(len))
			if common.Error(err) {
				return socksVersion, "", 0, err
			}

			clientPassword := string(buf)

			if (*username != "" && *username != clientUsername) || (*password != "" && *password != clientPassword) {
				// access denied

				err = writeBytes(conn, []byte{SOCKS5, 255})
				if common.Error(err) {
					return socksVersion, "", 0, err
				}

				return socksVersion, "", 0, fmt.Errorf("invalid credentials", buf)
			}

			// access granted

			err = writeBytes(conn, []byte{SOCKS5, 0})
			if common.Error(err) {
				return socksVersion, "", 0, err
			}
		}

		buf, err = readBytes(conn, 2)
		if common.Error(err) {
			return socksVersion, "", 0, err
		}

		if buf[0] != SOCKS5 {
			return socksVersion, "", 0, fmt.Errorf("Expected SOCKS 5 version failed: %d", buf[0])
		}

		mode := buf[1]
		if mode != MODE_TCP_STREAM {
			return socksVersion, "", 0, fmt.Errorf("Unknown SOCKS mode: %d", buf[0])
		}

		common.Debug("Requested SOCKS mode : %d", mode)

		buf, err = readBytes(conn, 2)
		if common.Error(err) {
			return socksVersion, "", 0, err
		}

		if buf[0] != 0 {
			return socksVersion, "", 0, fmt.Errorf("Expected 0 byte failed: %d", buf[0])
		}

		switch buf[1] {
		case 1: // IPv4
			buf, err = readBytes(conn, 4)
			if common.Error(err) {
				return socksVersion, "", 0, err
			}

			hostname = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
		case 3: // Domainname
			buf, err = readBytes(conn, 1)
			if common.Error(err) {
				return socksVersion, "", 0, err
			}

			lenDomainName := buf[0]
			buf, err = readBytes(conn, int(lenDomainName))
			if common.Error(err) {
				return socksVersion, "", 0, err
			}

			hostname = string(buf)
		case 4: // IPv6
			buf, err = readBytes(conn, 16)
			if common.Error(err) {
				return socksVersion, "", 0, err
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

		buf, err = readBytes(conn, 2)
		if common.Error(err) {
			return socksVersion, "", 0, err
		}

		port = int(int(buf[0])*256) + int(buf[1])
	} else {
		buf, err = readBytes(conn, 1)
		if common.Error(err) {
			return socksVersion, "", 0, err
		}

		// read mode

		mode := buf[0]
		if mode != MODE_TCP_STREAM {
			return socksVersion, "", 0, fmt.Errorf("unknown SOCKS mode: %d", buf[0])
		}

		common.Debug("Request SOCKS mode : %d", mode)

		// read port

		buf, err = readBytes(conn, 2)
		if common.Error(err) {
			return socksVersion, "", 0, err
		}

		port = int(int(buf[0])*256) + int(buf[1])

		// read IP address

		buf, err = readBytes(conn, 4)
		if common.Error(err) {
			return socksVersion, "", 0, err
		}

		// socks4 or socks4a ?

		if buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[3] != 0 {
			common.Debug("Request SOCKS protocol: 4a")

			// socks4a

			// user
			buf, err = readTill0(conn)
			if common.Error(err) {
				return socksVersion, "", 0, err
			}

			// domain
			buf, err = readTill0(conn)
			if common.Error(err) {
				return socksVersion, "", 0, err
			}

			hostname = string(buf)
		} else {
			common.Debug("Request SOCKS protocol: 4")

			// socks4

			hostname = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])

			_, err = readTill0(conn)
			if common.Error(err) {
				return socksVersion, "", 0, err
			}
		}
	}

	return socksVersion, hostname, port, nil
}

func runProxyClient(client *common.NetworkConnection) {
	defer func() {
		common.Debug("Client disconnected: %v\n", client.Socket)

		common.Error(client.Close())
	}()

	common.DebugFunc("Local: %v Remote %v", client.Socket.LocalAddr(), client.Socket.RemoteAddr())

	socksVersion, hostname, port, err := handshake(client.Socket)
	if common.Error(err) {
		return
	}

	common.Debug("Remote connection to: %s:%d", hostname, port)

	remoteClient, _ := common.NewNetworkClient(fmt.Sprintf("%s:%d", hostname, port), nil)

	remoteConn, err := remoteClient.Connect()
	if common.Error(err) {
		if socksVersion == 4 {
			err := writeBytes(client.Socket, []byte{0, byte(SOCKS4_REQUEST_REJECTED), 0, 0, 0, 0, 0, 0})
			if common.Error(err) {
				return
			}
		} else {
			var b bytes.Buffer

			b.WriteByte(SOCKS5)
			b.WriteByte(SOCKS5_REQUEST_REJECTED)
			b.WriteByte(0)
			b.WriteByte(3)
			b.WriteByte(byte(len(hostname)))
			b.Write([]byte(hostname))
			b.WriteByte(0)
			b.WriteByte(0)

			err = writeBytes(client.Socket, b.Bytes())
			if common.Error(err) {
				return
			}
		}

		return
	}

	if socksVersion == SOCKS4 {
		err := writeBytes(client.Socket, []byte{0, byte(SOCKS4_REQUEST_GRANTED), 0, 0, 0, 0, 0, 0})
		if common.Error(err) {
			return
		}
	} else {
		var b bytes.Buffer

		b.WriteByte(SOCKS5)
		b.WriteByte(SOCKS5_REQUEST_GRANTED)
		b.WriteByte(0)
		b.WriteByte(3)
		b.WriteByte(byte(len(hostname)))
		b.Write([]byte(hostname))
		b.WriteByte(byte(port / 256))
		b.WriteByte(byte(port % 256))

		err = writeBytes(client.Socket, b.Bytes())
		if common.Error(err) {
			return
		}
	}

	defer func() {
		common.Error(remoteConn.Close())
	}()

	ctx, cancel := context.WithCancel(context.Background())

	common.DataTransfer(ctx, cancel, "proxyclient", client, fmt.Sprintf("%s:%d", hostname, port), remoteConn)
}

func setupTLS() (*tls.Config, error) {
	common.DebugFunc()

	if !*useTls {
		return nil, nil
	}

	tlsConfig, err := common.NewTlsConfigFromFlags()
	if common.Error(err) {
		return nil, err
	}

	if !common.FileExists(*common.FlagTlsCertificate) {
		ba, err := common.TlsConfigToP12(tlsConfig, *common.FlagTlsPassword)
		if common.Error(err) {
			return nil, err
		}

		err = os.WriteFile(common.AppFilename(".p12"), ba, os.ModePerm)
		if common.Error(err) {
			return nil, err
		}
	}

	return tlsConfig, nil
}

func runProxyServer() error {
	common.DebugFunc()

	tlsConfig, err := setupTLS()
	if common.Error(err) {
		return err
	}

	server, err = common.NewNetworkServer(*serverAddress, tlsConfig)
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

			go func() {
				defer common.UnregisterGoRoutine(common.RegisterGoRoutine(1))

				runProxyClient(client)
			}()
		}
	}()

	return nil
}

func start() error {
	var errProxy error
	var errDns error

	go func() {
		defer common.UnregisterGoRoutine(common.RegisterGoRoutine(1))

		errProxy = runProxyServer()
	}()

	common.Sleep(common.MillisecondToDuration(*common.FlagServiceTimeout))

	if common.Error(errProxy) {
		return errProxy
	}

	if common.Error(errDns) {
		return errDns
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
	common.Run(nil)
}
