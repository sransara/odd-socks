package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/sransara/odd-socks/pkg/oddsocks"
)

const CONN_HOST = "localhost:3030"

func main() {

	var laddr string
	flag.StringVar(&laddr, "laddr", ":0", "Specify host:port to listen for incoming SOCKS connections")

	flag.Parse()
	if flag.NArg() > 0 {
		flag.Usage()
		return
	}

	listener, err := net.Listen("tcp", laddr)
	if err != nil {
		log.Fatal(err)
		return
	}

	defer listener.Close()

	fmt.Println("Listening on " + listener.Addr().String())

	ctx := context.Background()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
			continue
		}

		go serveConnection(ctx, conn)
	}
}

func serveConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var currHandler oddsocks.StateHandle
	var err error

	currHandler = oddsocks.HandleAuthNegotiation
	for {
		currHandler, err = currHandler(ctx, conn)

		if err != nil {
			fmt.Println(err)
		}

		if currHandler == nil {
			break
		}
	}
}
