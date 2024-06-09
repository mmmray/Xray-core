package transportcommon

type ConnectionApplicationProtocol interface {
	GetConnectionApplicationProtocol() (string, error)
}
