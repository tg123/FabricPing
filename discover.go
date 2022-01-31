package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/tg123/phabrik/federation"
	"github.com/tg123/phabrik/lease"
	"github.com/tg123/phabrik/transport"
)

func discover(conn net.Conn, tlsconf *tls.Config, fabricaddr string) error {
	if strings.ToLower(fabricaddr) == "auto" {
		ip, err := guessLocalIp()
		if err != nil {
			return err
		}
		fabricaddr = net.JoinHostPort(ip, "0")
	}

	s, err := transport.ListenTCP(fabricaddr, transport.ServerConfig{
		Config: transport.Config{
			TLS: tlsconf,
		},
	})
	if err != nil {
		return err
	}

	log.Printf("fabric agent listening at [%v]", s.Addr().String())

	// dummy lease agent here only, do nothing
	leaseConfig := lease.AgentConfig{}
	leaseConfig.SetDefault()

	leaselistener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", "0"))
	if err != nil {
		return err
	}

	l, err := lease.NewAgent(leaseConfig, leaselistener, func(addr string) (net.Conn, error) { return nil, nil })
	if err != nil {
		return err
	}

	now := int(time.Now().Unix())
	fakeid := federation.NodeIDFromMD5(strconv.Itoa(now))
	myid := federation.NodeIDFromMD5("FabricPing")

	config := federation.SiteNodeConfig{
		ClientTLS:       tlsconf,
		TransportServer: s,
		LeaseAgent:      l,
		Instance: federation.NodeInstance{
			Id:         myid,
			InstanceId: uint64(now),
		},
		SeedNodes: []federation.SeedNodeInfo{
			{
				Id:      fakeid,
				Address: conn.RemoteAddr().String(),
			},
		},
	}

	sitenode, err := federation.NewSiteNode(config)
	if err != nil {
		return err
	}
	go sitenode.Serve()
	defer sitenode.Close()

	parteners, err := sitenode.Discover(context.Background())
	if err != nil {
		return err
	}

	zero := federation.NodeID{}

	fmt.Printf("%v\t%v\t%v", "InstanceId", "Address", "Phase")
	fmt.Println()

	for _, p := range parteners {
		if p.Instance.Id == fakeid {
			continue
		}

		if p.Instance.Id == myid {
			continue
		}

		fmt.Printf("%v\t%v\t%v", p.Instance, p.Address, p.Phase)

		if p.Token.Range.Contains(zero) && p.Phase == federation.NodePhaseRouting {
			fmt.Printf("\tFMM")
		}

		fmt.Println()

	}

	return nil
}
