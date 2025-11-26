package ackhandler

import (
	"github.com/Noooste/uquic-go/internal/protocol"
	"github.com/Noooste/uquic-go/internal/utils"
	"github.com/Noooste/uquic-go/qlogwriter"
)

// [UQUIC]
func NewUAckHandler(
	initialPacketNumber protocol.PacketNumber,
	initialMaxDatagramSize protocol.ByteCount,
	rttStats *utils.RTTStats,
	connStats *utils.ConnectionStats,
	clientAddressValidated bool,
	enableECN bool,
	pers protocol.Perspective,
	tracer qlogwriter.Recorder,
	logger utils.Logger,
) (SentPacketHandler, ReceivedPacketHandler) {
	sph := newSentPacketHandler(
		initialPacketNumber,
		initialMaxDatagramSize,
		rttStats,
		connStats,
		clientAddressValidated,
		enableECN,
		pers,
		tracer,
		logger,
	)
	return &uSentPacketHandler{
		sentPacketHandler: sph,
	}, newReceivedPacketHandler(sph, logger)
}
