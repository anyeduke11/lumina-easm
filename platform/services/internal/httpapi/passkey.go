// httpapi/passkey.go — passkey（ES256 challenge-response）step-up 端点。
package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
)

func (s *Server) handlePasskeyChallenge(w http.ResponseWriter, r *http.Request) {
	if s.passkey == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "passkey_unavailable", "passkey 未配置")
		return
	}
	c, err := s.passkey.Challenge()
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"challenge": c})
}

func (s *Server) handlePasskeyVerify(w http.ResponseWriter, r *http.Request) {
	if s.passkey == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "passkey_unavailable", "passkey 未配置")
		return
	}
	var in map[string]string
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	tok, err := s.passkey.Verify(in["challenge"], in["signature"])
	if err != nil {
		writeError(w, requestIDOf(r), http.StatusUnauthorized, "passkey_invalid", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"stepup_token": tok})
}

// requirePasskeyStepUp 在配置了 passkey 且 method=passkey 时强制 step-up token。
// 未配置 passkey 时保持既有确认兼容（method 仅作标签），配置后即密码学校验。
func (s *Server) requirePasskeyStepUp(w http.ResponseWriter, r *http.Request, method string) bool {
	if s.passkey == nil || method != "passkey" {
		return true
	}
	tok := r.Header.Get("X-EASM-StepUp")
	if tok == "" || !s.passkey.ValidateStepUp(tok) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "passkey_required",
			"method=passkey 需要有效 X-EASM-StepUp（先 POST /v1/session/passkey/verify）")
		return false
	}
	return true
}
