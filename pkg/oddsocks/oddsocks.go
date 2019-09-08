package oddsocks

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
)

type StateHandle func(context.Context, net.Conn) (StateHandle, error)

type ReplyCode uint8
type AddrType uint8

const (
	Version5 = 0x05

	AuthMethodNoAuth           = 0
	AuthMethodGSSAPI           = 1
	AuthMethodUsernamePassword = 2
	AuthMethodNoAcceptable     = 0xFF

	CmdCommandConnect = 1
	CmdCommandBind    = 2
	CmdCommandUDP     = 3

	AddrTypeIPv4   AddrType = 1
	AddrTypeIPv6   AddrType = 4
	AddrTypeDomain AddrType = 3

	CmdReplySucceeded            ReplyCode = 0x00
	CmdReplyServerFail           ReplyCode = 0x01
	CmdReplyDeclinedByRuleset    ReplyCode = 0x02
	CmdReplyNetworkUnreachable   ReplyCode = 0x03
	CmdReplyHostUnreachable      ReplyCode = 0x04
	CmdReplyConnectionRefused    ReplyCode = 0x05
	CmdReplyTtlExpired           ReplyCode = 0x06
	CmdReplyCmdNotSupported      ReplyCode = 0x07
	CmdReplyAddrTypeNotSupported ReplyCode = 0x08
)

type CmdError struct {
	error
	Code ReplyCode
}

type AuthNegotiationRequest struct {
	Version  uint8
	NMethods uint8
	Methods  []uint8
}

func ProcessAuthNegotiationRequest(conn net.Conn) (AuthNegotiationRequest, error) {
	var request AuthNegotiationRequest
	var err error

	var version uint8
	err = binary.Read(conn, binary.BigEndian, &version)
	if err != nil {
		return request, err
	}

	var nmethods uint8
	err = binary.Read(conn, binary.BigEndian, &nmethods)
	if err != nil {
		return request, err
	}

	methods := make([]uint8, nmethods)
	err = binary.Read(conn, binary.BigEndian, methods)
	if err != nil {
		return request, err
	}

	request = AuthNegotiationRequest{
		version,
		nmethods,
		methods,
	}

	return request, nil
}

func ActionAuthNegotiation(conn net.Conn, chosenMethod uint8) error {
	reply := []uint8{Version5, chosenMethod}
	err := binary.Write(conn, binary.BigEndian, reply)
	return err
}

func HandleAuthNegotiation(ctx context.Context, conn net.Conn) (StateHandle, error) {
	var err error

	request, err := ProcessAuthNegotiationRequest(conn)
	if err != nil {
		return nil, err
	}

	if request.Version != Version5 {
		return nil, errors.New("Version mismatch")
	}

	for _, method := range request.Methods {
		if method == AuthMethodNoAuth {
			err = ActionAuthNegotiation(conn, AuthMethodNoAuth)

			if err != nil {
				return nil, err
			}

			return HandleCmdRequest, nil
		}
	}

	err = ActionAuthNegotiation(conn, AuthMethodNoAcceptable)
	if err != nil {
		return nil, err
	}
	return nil, errors.New("No acceptable authentication method")
}

type SockName struct {
	Type     AddrType
	Port     uint16
	HostIP   net.IP
	Hostname string
}

func (sn SockName) String() string {
	var host string
	if sn.Type == AddrTypeDomain {
		host = sn.Hostname
	} else {
		host = sn.HostIP.String()
	}

	var port string = strconv.Itoa(int(sn.Port))

	return net.JoinHostPort(host, port)
}

func (sn SockName) Raw() ([]uint8, error) {
	var raw []uint8

	raw = []uint8{uint8(sn.Type)}

	var rawHost []uint8
	if sn.Type == AddrTypeIPv4 {
		if hostIP := sn.HostIP.To4(); hostIP != nil {
			rawHost = make([]uint8, len(hostIP))
			copy(rawHost, hostIP)
		} else {
			return raw, errors.New("Type and IP incompatible in sockname")
		}
	} else if sn.Type == AddrTypeIPv6 {
		if hostIP := sn.HostIP.To16(); hostIP != nil {
			rawHost = make([]uint8, len(hostIP))
			copy(rawHost, hostIP)
		} else {
			return raw, errors.New("Type and IP incompatible in sockname")
		}
	} else if sn.Type == AddrTypeDomain {
		hostnameLength := uint8(len(sn.Hostname))
		rawHost = []uint8{hostnameLength}
		rawHost = append(rawHost, []uint8(sn.Hostname)...)
	} else {
		return raw, errors.New("Uninitialized type in sockname")
	}

	raw = append(raw, rawHost...)

	rawPort := make([]uint8, 2)
	binary.BigEndian.PutUint16(rawPort, sn.Port)

	raw = append(raw, rawPort...)

	return raw, nil
}

func (sn SockName) GetOutboundInterfaceIP() (string, error) {
	var ifip string
	conn, err := net.Dial("udp", sn.String())
	if err != nil {
		return ifip, err
	}
	defer conn.Close()

	ifip, _, err = net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return ifip, err
	}

	return ifip, nil
}

func GetSockNameFromAddr(addr net.Addr) (SockName, error) {
	var sn SockName
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return sn, err
	}

	if sn.HostIP = net.ParseIP(host).To4(); sn.HostIP != nil {
		sn.Type = AddrTypeIPv4
	} else if sn.HostIP = net.ParseIP(host).To16(); sn.HostIP != nil {
		sn.Type = AddrTypeIPv6
	} else {
		sn.Hostname = host
		sn.Type = AddrTypeDomain
	}

	portUint, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return sn, err
	}
	sn.Port = uint16(portUint)

	return sn, nil
}

type CmdRequest struct {
	Version     uint8
	Command     uint8
	Destination SockName
}

func ProcessCmdRequest(conn net.Conn) (CmdRequest, error) {
	var request CmdRequest
	var err error

	var version uint8
	err = binary.Read(conn, binary.BigEndian, &version)
	if err != nil {
		return request, err
	}

	var command uint8
	err = binary.Read(conn, binary.BigEndian, &command)
	if err != nil {
		return request, err
	}

	var reserved uint8
	err = binary.Read(conn, binary.BigEndian, &reserved)
	if err != nil {
		return request, err
	}

	var addrType AddrType
	err = binary.Read(conn, binary.BigEndian, &addrType)
	if err != nil {
		return request, err
	}

	var destination SockName
	var dstHostIPRaw []byte
	if addrType == AddrTypeIPv4 {
		dstHostIPRaw = make([]uint8, 4)
		err = binary.Read(conn, binary.BigEndian, dstHostIPRaw)
		if err != nil {
			return request, err
		}
		destination.Type = AddrTypeIPv4
		destination.HostIP = net.IP(dstHostIPRaw)
	} else if addrType == AddrTypeIPv6 {
		dstHostIPRaw = make([]uint8, 16)
		err = binary.Read(conn, binary.BigEndian, dstHostIPRaw)
		if err != nil {
			return request, err
		}
		destination.Type = AddrTypeIPv6
		destination.HostIP = net.IP(dstHostIPRaw)
	} else if addrType == AddrTypeDomain {
		var dstHostnameLength uint8
		err = binary.Read(conn, binary.BigEndian, &dstHostnameLength)
		if err != nil {
			return request, err
		}

		dstHostnameRaw := make([]byte, dstHostnameLength)
		err = binary.Read(conn, binary.BigEndian, dstHostnameRaw)
		if err != nil {
			return request, err
		}

		destination.Type = AddrTypeDomain
		destination.Hostname = string(dstHostnameRaw)
	} else {
		return request, CmdError{errors.New("request.AddrType not supported"), CmdReplyAddrTypeNotSupported}
	}

	var dstPort uint16
	err = binary.Read(conn, binary.BigEndian, &dstPort)
	if err != nil {
		return request, err
	}
	destination.Port = dstPort

	request = CmdRequest{
		Version5,
		command,
		destination,
	}

	return request, nil
}

func StartTCPRelay(ctx context.Context, clientConn net.Conn, remoteConn net.Conn) {
	stop := make(chan struct{})

	go func() { io.Copy(clientConn, remoteConn); stop <- struct{}{} }()
	go func() { io.Copy(remoteConn, clientConn); stop <- struct{}{} }()

	select {
	case <-stop:
	case <-ctx.Done():
		return
	}
}

func ActionCmdError(conn net.Conn, errorCode ReplyCode) error {
	reply := []uint8{Version5, uint8(errorCode), 0x00, uint8(AddrTypeDomain), 0x00, 0x00, 0x00}
	err := binary.Write(conn, binary.BigEndian, reply)
	return err
}

func MakeCmdReply(code ReplyCode, addr net.Addr) ([]uint8, error) {
	reply := []uint8{
		Version5,
		uint8(code),
		0x00,
	}

	sockName, err := GetSockNameFromAddr(addr)
	if err != nil {
		return reply, err
	}
	rawSockName, err := sockName.Raw()
	if err != nil {
		return reply, err
	}
	reply = append(reply, rawSockName...)

	return reply, nil
}

func ActionCmdConnect(ctx context.Context, conn net.Conn, request CmdRequest) error {
	var err error

	var dialer net.Dialer

	remoteConn, err := dialer.DialContext(ctx, "tcp", request.Destination.String())
	if err != nil {
		return CmdError{err, CmdReplyHostUnreachable}
	}
	defer remoteConn.Close()

	reply, err := MakeCmdReply(CmdReplySucceeded, remoteConn.LocalAddr())
	if err != nil {
		return err
	}

	err = binary.Write(conn, binary.BigEndian, reply)
	if err != nil {
		return err
	}

	StartTCPRelay(ctx, conn, remoteConn)

	return nil
}

func ActionCmdBind(ctx context.Context, conn net.Conn, request CmdRequest) error {
	remoteListenerLocalInterfaceIP, err := request.Destination.GetOutboundInterfaceIP()
	if err != nil {
		return err
	}

	remoteListener, err := net.Listen("tcp", net.JoinHostPort(remoteListenerLocalInterfaceIP, "0"))
	if err != nil {
		return err
	}
	defer remoteListener.Close()

	reply1, err := MakeCmdReply(CmdReplySucceeded, remoteListener.Addr())
	if err != nil {
		return err
	}

	err = binary.Write(conn, binary.BigEndian, reply1)
	if err != nil {
		return err
	}

	for {
		remoteConn, err := remoteListener.Accept()
		if err == nil {
			continue
		}
		addr, ok := remoteConn.RemoteAddr().(*net.TCPAddr)
		if !ok {
			remoteConn.Close()
			continue
		}

		if addr.IP.Equal(request.Destination.HostIP) {
			reply2, err := MakeCmdReply(CmdReplySucceeded, addr)
			if err != nil {
				remoteConn.Close()
				return err
			}

			err = binary.Write(conn, binary.BigEndian, reply2)
			if err != nil {
				remoteConn.Close()
				return err
			}

			StartTCPRelay(ctx, conn, remoteConn)

			remoteConn.Close()
			return nil
		} else {
			remoteConn.Close()
			continue
		}
	}
}

func StartUDPRelay(ctx context.Context, clientConn net.PacketConn, clientSockName SockName, remoteConn net.PacketConn) {
	stop := make(chan struct{})

	clientAddr, err := net.ResolveUDPAddr("udp", clientSockName.String())
	if err != nil {
		return
	}

	// TODO: brake this go routine in to a new function (part of issue #4)
	// go routine to read from client unwrap packet and write data to destination
	go func() {
		buffer := make([]byte, 2048)

		for {
			n, addr, err := clientConn.ReadFrom(buffer)
			if err != nil {
				stop <- struct{}{}
				return
			}
			udpAddr, ok := addr.(*net.UDPAddr)
			if ok && udpAddr.IP.Equal(clientSockName.HostIP) && (udpAddr.Port == int(clientSockName.Port)) {
				// 2 reserved bytes
				si := 2
				// 1 frag byte
				frag := buffer[si]
				if frag > 0 {
					stop <- struct{}{}
					return
				}
				si += 1
				// 1 address type byte
				addrType := AddrType(buffer[si])
				si += 1
				// variable dst.addr
				var dstHost string
				if addrType == AddrTypeIPv4 {
					ni := si + 4
					dstHost = net.IP(buffer[si:ni]).String()
					si = ni
				} else if addrType == AddrTypeIPv6 {
					ni := si + 16
					dstHost = net.IP(buffer[si:ni]).String()
					si = ni
				} else if addrType == AddrTypeDomain {
					length := buffer[si]
					si += 1
					ni := si + int(length)
					dstHost = string(buffer[si:ni])
					si = ni
				}
				// 2 dst.port
				dstPortRaw := binary.BigEndian.Uint16(buffer[si : si+2])
				dstPort := strconv.FormatUint(uint64(dstPortRaw), 10)
				si += 2

				// variable data
				data := buffer[si:n]

				raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(dstHost, dstPort))
				if err != nil {
					stop <- struct{}{}
					return
				}

				_, err = remoteConn.WriteTo(data, raddr)
				if err != nil {
					stop <- struct{}{}
					return
				}
			}
		}
	}()

	// TODO: brake this go routine in to a new function (part of issue #4)
	// go routine to read from remote; wrap the data and write to client
	go func() {
		buffer := make([]byte, 2048)

		for {
			n, remoteAddr, err := remoteConn.ReadFrom(buffer)
			if err != nil {
				stop <- struct{}{}
				return
			}

			// 2 reserved bytes = {0,0}
			// 1 frag byte = 0
			reply := []byte{0, 0, 0}

			// 1 addr type
			// variable dst address
			// 2 port bytes
			remoteSockName, err := GetSockNameFromAddr(remoteAddr)
			if err != nil {
				stop <- struct{}{}
				return
			}

			remoteSockNameRaw, err := remoteSockName.Raw()
			if err != nil {
				stop <- struct{}{}
				return
			}

			reply = append(reply, remoteSockNameRaw...)

			// variable data
			reply = append(reply, buffer[:n]...)

			_, err = remoteConn.WriteTo(reply, clientAddr)
			if err != nil {
				stop <- struct{}{}
				return
			}
		}
	}()

	select {
	case <-stop:
	case <-ctx.Done():
		return
	}
}

func ActionCmdUDP(ctx context.Context, conn net.Conn, request CmdRequest) error {
	connLocalAddr, _ := conn.LocalAddr().(*net.TCPAddr)

	clientConn, err := net.ListenPacket("udp", net.JoinHostPort(connLocalAddr.IP.String(), "0"))
	if err != nil {
		return err
	}
	defer clientConn.Close()

	reply, err := MakeCmdReply(CmdReplySucceeded, clientConn.LocalAddr())
	if err != nil {
		return err
	}

	err = binary.Write(conn, binary.BigEndian, reply)
	if err != nil {
		return err
	}

	remoteConn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return err
	}
	defer remoteConn.Close()

	StartUDPRelay(ctx, clientConn, request.Destination, remoteConn)

	return nil
}

func HandleCmdRequest(ctx context.Context, conn net.Conn) (StateHandle, error) {
	var err error

	request, err := ProcessCmdRequest(conn)
	if err != nil {
		return nil, err
	}

	if request.Version != Version5 {
		return nil, errors.New("Version mismatch")
	}

	if request.Command == CmdCommandConnect {
		err = ActionCmdConnect(ctx, conn, request)
		if cerr, ok := err.(CmdError); ok {
			err = ActionCmdError(conn, cerr.Code)
		}
		return nil, err
	} else if request.Command == CmdCommandBind {
		err = ActionCmdBind(ctx, conn, request)
		if cerr, ok := err.(CmdError); ok {
			err = ActionCmdError(conn, cerr.Code)
		}
		return nil, err
	} else if request.Command == CmdCommandUDP {
		err = ActionCmdUDP(ctx, conn, request)
		if cerr, ok := err.(CmdError); ok {
			err = ActionCmdError(conn, cerr.Code)
		}
		return nil, err
	} else {
		cerr := CmdError{
			errors.New("Command not supported"),
			CmdReplyCmdNotSupported,
		}
		err = ActionCmdError(conn, cerr.Code)
		return nil, err
	}
}
