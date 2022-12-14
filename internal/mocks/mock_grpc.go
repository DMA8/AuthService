// Code generated by MockGen. DO NOT EDIT.
// Source: internal/ports/grpc.go

// Package mock_ports is a generated GoMock package.
package mock_ports

import (
	gomock "github.com/golang/mock/gomock"
)

// MockClientAuth is a mock of ClientAuth interface.
type MockClientAuth struct {
	ctrl     *gomock.Controller
	recorder *MockClientAuthMockRecorder
}

// MockClientAuthMockRecorder is the mock recorder for MockClientAuth.
type MockClientAuthMockRecorder struct {
	mock *MockClientAuth
}

// NewMockClientAuth creates a new mock instance.
func NewMockClientAuth(ctrl *gomock.Controller) *MockClientAuth {
	mock := &MockClientAuth{ctrl: ctrl}
	mock.recorder = &MockClientAuthMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockClientAuth) EXPECT() *MockClientAuthMockRecorder {
	return m.recorder
}
