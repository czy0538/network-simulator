package network_simulator

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"gitee.com/czy_hit/softbus-go/net/tun"
	"gitee.com/czy_hit/softbus-go/util/iptool"
	"github.com/gookit/config/v2"
	"github.com/gookit/config/v2/yamlv3"
	"github.com/quic-go/quic-go"
	"log/slog"
	"math/big"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"time"
)

const (
	lAddr   = "0.0.0.0:2345"
	BUFSIZE = 4096
)

type TunDevice struct {
	name   string
	device tun.Device
	ip     string
}

type IPTable sync.Map

func (t *IPTable) Add(vIP, rIP net.IP) {
	(*sync.Map)(t).Store(vIP, rIP)
}

func (t *IPTable) Get(vIP net.IP) (net.IP, bool) {
	rIP, ok := (*sync.Map)(t).Load(vIP)
	return rIP.(net.IP), ok
}

type ChanTable sync.Map

func (t *ChanTable) Add(vIP net.IP, ch chan []byte) {
	(*sync.Map)(t).Store(vIP, ch)
}
func (t *ChanTable) Get(vIP net.IP) (chan []byte, bool) {
	ch, ok := (*sync.Map)(t).Load(vIP)
	return ch.(chan []byte), ok
}

type DevTable sync.Map

func (t *DevTable) Add(vIP net.IP, dev *TunDevice) {
	(*sync.Map)(t).Store(vIP, dev)
}

func (t *DevTable) Get(vIP net.IP) (*TunDevice, bool) {
	dev, ok := (*sync.Map)(t).Load(vIP)
	return dev.(*TunDevice), ok
}

var iptable *IPTable     // virtual ip -> real ip
var chanTable *ChanTable // virtual IP -> channel(quic client)
var devTable *DevTable   // virtual IP -> tun device

var tunName = []string{"mptest-1", "mptest-2"}
var tunIPPrefix string
var tunIfaceNum = 2
var tunInterface []*TunDevice

func init() {
	config.WithOptions(config.ParseEnv)
	config.AddDriver(yamlv3.Driver)
	err := config.LoadFiles("config_example.yaml")
	if err != nil {
		panic(err)
	}
	ipt := config.StringMap("map1")
	for k, v := range ipt {
		iptable.Add(net.ParseIP(k), net.ParseIP(v))
	}
}

func main() {
	flag.StringVar(&tunIPPrefix, "prefix", "10.0.0.", "tun ip prefix")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	errChan := make(chan struct{})
	go runServer(ctx, errChan)
	runClinet(ctx)

	for i := 0; i < tunIfaceNum; i++ {
		dev, name, err := tun.NewWater(tunName[i])
		if err != nil {
			slog.Error("create new tun device failed", err)
		}
		tunInterface = append(tunInterface, &TunDevice{name: name, device: dev, ip: tunIPPrefix + strconv.Itoa(i)})
		err = tun.SetupIfce(net.IPNet{
			IP:   net.ParseIP(tunInterface[i].ip),
			Mask: net.IPv4Mask(255, 255, 255, 0),
		}, name)
		if err != nil {
			slog.Error("setup tun device failed", err)
		}
		devTable.Add(net.ParseIP(tunInterface[i].ip), tunInterface[i])
		go func(dev tun.Device) {
			readMessage(ctx, dev, func(vIP net.IP, buf []byte) {
				if ch, ok := chanTable.Get(vIP); ok {
					ch <- buf
				} else {
					slog.Error("can not find channel for ", vIP)
				}

			})
		}(dev)
		defer func() {
			tun.DownIfce(name)
		}()
	}

	select {
	case s := <-interrupt:
		slog.Info("interrupt by ", s)
	case <-ctx.Done():
		slog.Info("ctx done")
	case <-errChan:
		slog.Error("error occur")
	}
}

func readMessage(ctx context.Context, dev tun.Device, send func(rIP net.IP, buf []byte)) {
	bufs := make([][]byte, dev.BatchSize())
	buf := make([]byte, BUFSIZE)
	bufs[0] = buf
	size := make([]int, dev.BatchSize())
	for {
		select {
		case <-ctx.Done():
		default:
			_, err := dev.Read(bufs, size, 0)
			if err != nil {
				slog.Error("read message failed", err)
			}
			packet := buf[:size[0]]

			// TODO:Add IPv6 support
			if iptool.IsIPv4(packet) {
				slog.Info("get a packet form %v:%d,to %v:%d\n", iptool.IPv4Source(packet), iptool.IPv4SourcePort(packet), iptool.IPv4Destination(packet), iptool.IPv4DestinationPort(packet))
				vIP := iptool.IPv4Destination(packet)
				send(vIP, packet)
				slog.Info("send %d bytes to ", vIP.String())
			} else {
				slog.Info("is not a ipv4 packet")
			}
		}
	}
}

func writeMessage(dev tun.Device, packet []byte) error {
	if iptool.IsIPv4(packet) {
		slog.Info("receive message:%d \n", len(packet))
		srcIP := iptool.IPv4Source(packet)
		dstIP := iptool.IPv4Destination(packet)
		srcPort := iptool.IPv4SourcePort(packet)
		dstPort := iptool.IPv4DestinationPort(packet)
		slog.Info("get a packet form %v:%d,to %v:%d\n", srcIP, srcPort, dstIP, dstPort)
		n, err := dev.Write(append([][]byte{}, packet), 0)
		if err != nil {
			return err
		}
		slog.Info("write %d success\n", n)
	} else {
		slog.Info("is not a ipv4 packet")
	}
	return nil
}

func initServer() (*quic.Listener, error) {
	listener, err := quic.ListenAddr(lAddr, generateTLSConfig(), nil)
	return listener, err
}

func initClient(ctx context.Context, rAddr string) (chan []byte, error) {
	session, err := quic.DialAddr(ctx, rAddr, &tls.Config{InsecureSkipVerify: true}, nil)
	if err != nil {
		return nil, err
	}
	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	pChan := make(chan []byte, 10)
	go func(ctx context.Context, stream quic.Stream, pChan chan []byte) {

		for {
			select {
			case <-ctx.Done():
				return
			case buf := <-pChan:
				_, err := stream.Write(buf)
				if err != nil {
					slog.Error(err.Error())
				}
			}

		}
	}(ctx, stream, pChan)
	return pChan, nil
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-echo-example"},
	}
}

func runServer(ctx context.Context, errChan chan struct{}) {
	var err error
	defer func() {
		if err != nil {
			slog.Error(err.Error())
			errChan <- struct{}{}
		}
	}()
	listener, err := initServer()
	if err != nil {
		return
	}
	defer listener.Close()

	for {
		select {
		case <-ctx.Done():
		default:
			var conn quic.Connection
			conn, err = listener.Accept(ctx)
			if err != nil {
				return
			}
			go handleConn(ctx, conn)
		}
	}

}

func handleConn(ctx context.Context, conn quic.Connection) {
	rIP := conn.RemoteAddr().String()
	for {
		select {
		case <-ctx.Done():
		default:
			stream, err := conn.AcceptStream(ctx)
			if err != nil {
				slog.Error(err.Error())
				return
			}
			go func(s quic.Stream) {
				buf := make([]byte, BUFSIZE)
				for {
					select {
					case <-ctx.Done():
						return
					default:
					}
					n, err := stream.Read(buf)
					if err != nil {
						slog.Error(err.Error())
						return
					}
					slog.Info("receive message from rIP", rIP, "vIp", iptool.IPv4Source(buf[:n]))
					if dev, ok := devTable.Get(iptool.IPv4Destination(buf[:n])); ok {
						err = writeMessage(dev.device, buf[:n])
						if err != nil {
							slog.Error(err.Error())
							return
						}
					} else {
						slog.Error("can not find channel for ", iptool.IPv4Source(buf[:n]))
						return
					}
				}
			}(stream)
		}
	}
}

func runClinet(ctx context.Context) {
	(*sync.Map)(iptable).Range(func(key, value interface{}) bool {
		vIP := key.(net.IP)
		rIP := value.(net.IP)
	InitClientLabel:
		pChan, err := initClient(ctx, rIP.String())
		if err != nil {
			if err.Error() == "timeout: handshake did not complete in time" {
				slog.Info("timeout,try again")
				time.Sleep(3 * time.Second)
				goto InitClientLabel
			} else {
				slog.Error(err.Error())
				return false
			}
		}
		chanTable.Add(vIP, pChan)
		return true
	})
}
