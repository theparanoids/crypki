package interceptor

import (
	"context"
	"google.golang.org/grpc/credentials"
	"log"
	"path"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const (
	// keyStartTimestamp is the key name for the starting time of a request (in seconds).
	keyStartTimestamp = "sts"

	// keyMethod is the key name for the grpc method.
	keyMethod = "mtd"

	// keyStatusCode is the key name for the response status code.
	keyStatusCode = "st"

	// keyDurationMs is the key name for the duration of the request (in milliseconds).
	keyDurationMs = "dur"

	// keyPrincipal is the key name for the common name of the peer certificate extracted from the context.
	keyPrincipal = "prin"

	// accessLogMsg is the special log message that will be used in access log so that it can
	// be used to distinguish from other server logs.
	accessLogMsg = "grpcAccessLog"
)

type accessLogInterceptor struct {
	timeNow       func() time.Time
}

func (i *accessLogInterceptor) Func(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	startTime := i.timeNow()
	resp, err := handler(ctx, req)
	elapsedTime := i.timeNow().Sub(startTime)

	log.Printf(`m=%s,%s=%s,%s=%f,%s=%s,%s=%d,%s=%d`,
		accessLogMsg,
		keyPrincipal, getPrincipalFromContext(ctx),
		keyStartTimestamp, float64(startTime.UnixNano())/float64(time.Second),
		keyMethod, path.Base(info.FullMethod),
		keyStatusCode, getStatus(err),
		keyDurationMs, elapsedTime.Milliseconds())
	return resp, err
}

func getPrincipalFromContext(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p == nil {
		return "unknown peer"
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "unknown tls info"
	}
	certs := tlsInfo.State.PeerCertificates
	if len(certs) == 0 || certs[0] == nil {
		return "peer certificate not found"
	}
	return certs[0].Subject.CommonName
}

func getStatus(err error) uint32 {
	statusErr := status.Convert(err)
	return uint32(statusErr.Code())
}

func AccessLogInterceptor() grpc.UnaryServerInterceptor {
	interceptor := &accessLogInterceptor{
		timeNow:       time.Now,
	}
	return interceptor.Func
}
