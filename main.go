package main

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/tg123/phabrik/lease"
	"github.com/tg123/phabrik/transport"
	"github.com/urfave/cli/v2"
)

func guessLocalIp() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		default:
			continue
		}

		if ip.IsLoopback() {
			continue
		}

		if ip.IsUnspecified() {
			continue
		}

		if ip.To4() == nil {
			continue
		}

		if !ip.IsPrivate() {
			continue
		}

		return ip.String(), nil
	}

	return "", fmt.Errorf("no ip found")
}

func leaseping(conn net.Conn, tlsconf *tls.Config, interval time.Duration, timeout time.Duration, leaseaddr string) error {
	config := lease.AgentConfig{
		TLS: tlsconf,
	}
	config.SetDefault()

	if strings.ToLower(leaseaddr) == "auto" {
		ip, err := guessLocalIp()
		if err != nil {
			return err
		}
		leaseaddr = net.JoinHostPort(ip, "0")
	}

	l, err := net.Listen("tcp", leaseaddr)
	if err != nil {
		return err
	}

	log.Printf("lease agent listening at [%v]", l.Addr().String())

	agent, err := lease.NewAgent(config, l, func(addr string) (net.Conn, error) {
		return conn, nil
	})

	if err != nil {
		return err
	}
	defer agent.Close()
	go agent.Wait()

	s, err := agent.Establish(conn.RemoteAddr().String())
	if err != nil {
		return err
	}

	log.Printf("starting lease ping")

	for {
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			now := time.Now()
			err := s.Ping(ctx)
			if err != nil {
				log.Printf("lease ping error %v", err)
				return
			}

			d := s.LastPongTime().Sub(now)
			log.Printf("lease pong from %v time = %v", conn.RemoteAddr().String(), d)
		}()

		time.Sleep(interval)
	}
}

func fabricping(conn net.Conn, tlsconf *tls.Config, interval time.Duration, timeout time.Duration) error {
	log.Printf("starting fabric handshake and send init transport message")
	c, err := transport.Connect(conn, transport.ClientConfig{
		Config: transport.Config{
			TLS: tlsconf,
		},
	})
	if err != nil {
		log.Fatalf("fabric level handshake failed, error: %v", err)
	}
	defer c.Close()
	go c.Wait()

	log.Printf("fabric level handshake success")

	for {
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			d, err := c.Ping(ctx)
			if err != nil {
				log.Printf("fabric heartbeat error: %v", err)
				return
			}

			log.Printf("fabric heartbeat response from %v time = %v", conn.RemoteAddr().String(), d)
		}()

		time.Sleep(interval)
	}
}

func main() {

	app := &cli.App{
		Name:      "Fabric Ping",
		Usage:     "Ping a Fabric/FabricLease endpoint",
		UsageText: "FabricPing [OPTIONS] <address:port>",
		Description: `Ping Fabric:  FabricPing 10.0.0.4:1025
Ping Lease:   FabricPing -l auto 10.0.0.4:1026
		`,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "lease-addr",
				Aliases: []string{"l"},
				Usage:   "Lease agent listening address, use [auto] to create one automatically",
			},
			&cli.StringFlag{
				Name:        "cert",
				Aliases:     []string{"c"},
				Usage:       "thumbprint, CN or a pem path to certificate",
				DefaultText: "search on the machine",
			},
			&cli.StringFlag{
				Name:  "cert-path",
				Usage: "certificate files search path",
				Value: certSearchPath,
			},
			&cli.DurationFlag{
				Name:    "interval",
				Aliases: []string{"t"},
				Value:   time.Second * 2,
			},
			&cli.DurationFlag{
				Name:  "timeout",
				Value: time.Second * 30,
			},
			&cli.BoolFlag{
				Name:  "non-secure",
				Value: false,
			},
		},

		Action: func(c *cli.Context) error {

			var remotetps []string
			tlsconf := &tls.Config{
				InsecureSkipVerify: true,
				VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					for _, rawCert := range rawCerts {
						cert, err := x509.ParseCertificate(rawCert)

						if err != nil {
							log.Printf("error read remote cert error %v", err)
							continue
						}

						valid := true
						valid = valid && !time.Now().After(cert.NotAfter)
						valid = valid && !time.Now().Before(cert.NotBefore)

						thumb := fmt.Sprintf("%x", sha1.Sum(rawCert))
						remotetps = append(remotetps, thumb)
						log.Printf("remote site is presenting certificate [CN=%v] [expired=%v] [not before=%v] [not after=%v] [thumbprint=%v]", cert.Subject.CommonName, !valid, cert.NotBefore, cert.NotAfter, thumb)
					}
					return nil
				},
				GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
					certkeyword := c.String("cert")
					if certkeyword != "" {
						cert, err := searchCert(certkeyword)
						if err != nil {
							return nil, fmt.Errorf("search cert return error: %v", err)
						}

						log.Printf("using certificate thumbprint [%v]", fmt.Sprintf("%x", sha1.Sum(cert.Certificate[0])))
						return cert, nil
					}

					for _, remotetp := range remotetps {
						if remotetp != "" {
							log.Printf("discovering certificate on machine with thumbprint [%v]", remotetp)
							cert, err := searchCert(remotetp)
							if err != nil {
								log.Printf("did not find certifcate thumbprint [%v], error: %v", remotetp, err)
								continue
							}

							return cert, nil
						}
					}

					return nil, fmt.Errorf("did not find any certificate")
				},
			}

			addr := c.Args().First()

			if addr == "" {
				return cli.ShowAppHelp(c)
			}

			if c.Bool("non-secure") {
				tlsconf = nil
			}

			timeout := c.Duration("timeout")
			interval := c.Duration("interval")
			certSearchPath = c.String("cert-path")

			log.Printf("start fabric ping target: %v, timeout %v", addr, timeout)

			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err != nil {
				return fmt.Errorf("cannot establish tcp connection to %v error: %v", addr, err)
			}
			defer conn.Close()

			log.Printf("tcp connected, resolved address: %v, local address: %v", conn.RemoteAddr().String(), conn.LocalAddr().String())

			leaseaddr := c.String("lease-addr")

			if leaseaddr != "" {
				log.Printf("starting lease ping, ctrl + c to break")
				return leaseping(conn, tlsconf, interval, timeout, leaseaddr)
			}

			log.Printf("starting fabric ping, ctrl + c to break")
			return fabricping(conn, tlsconf, interval, timeout)
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
