package uauth

import "errors"

var ErrInvalidRefreshToken error = errors.New("ErrInvalidRefreshToken")
var ErrInvalidUser error = errors.New("ErrInvalidUser")

func MachineError(readable error, details error) map[string]interface{} {
	return map[string]interface{}{
		"error":   readable.Error(),
		"details": details.Error(),
	}
}
