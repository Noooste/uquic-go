//go:build gomock || generate

package ackhandler

//go:generate sh -c "go tool mockgen -typed -build_flags=\"-tags=gomock\"  -package ackhandler -destination mock_sent_packet_tracker_test.go github.com/Noooste/uquic-go/internal/ackhandler SentPacketTracker"
type SentPacketTracker = sentPacketTracker

//go:generate sh -c "go tool mockgen -typed -build_flags=\"-tags=gomock\"  -package ackhandler -destination mock_ecn_handler_test.go github.com/Noooste/uquic-go/internal/ackhandler ECNHandler"
type ECNHandler = ecnHandler
