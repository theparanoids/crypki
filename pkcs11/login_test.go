// Copyright 2021 Yahoo.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pkcs11

import (
	"errors"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"
	p11 "github.com/miekg/pkcs11"

	"github.com/theparanoids/crypki/config"
	mock "github.com/theparanoids/crypki/pkcs11/mock_pkcs11"
)

func Test_openLoginSession(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pin     string
		slot    uint
		session p11.SessionHandle
		wantErr bool
		errMsg  map[string]error
	}{
		{
			name:    "good",
			wantErr: false,
		},
		{
			name:    "bad_OpenSession",
			wantErr: true,
			errMsg: map[string]error{
				"OpenSession": errors.New("failed to open a new session"),
			},
		},
		{
			name:    "bad_slot_pass",
			wantErr: true,
			errMsg: map[string]error{
				"Login": errors.New("bad pin"),
			},
		},
		{
			name:    "bad_user_already_login",
			wantErr: true,
			errMsg: map[string]error{
				"Login": errors.New("user already login"),
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockCtx := mock.NewMockPKCS11Ctx(mockCtrl)
			mockCtx.EXPECT().
				OpenSession(tt.slot, gomock.Any()).
				Return(tt.session, tt.errMsg["OpenSession"]).
				AnyTimes()

			mockCtx.EXPECT().
				Login(tt.session, p11.CKU_USER, gomock.Any()).
				Return(tt.errMsg["Login"]).
				AnyTimes()

			mockCtx.EXPECT().
				CloseSession(tt.session).
				Return(tt.errMsg["CloseSession"]).
				AnyTimes()

			_, err := openLoginSession(mockCtx, tt.slot, tt.pin)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, but got nil")
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

type mockHelper struct {
	keyMap             map[uint]*secureBuffer
	mockGetUserPinCode func(string) (*secureBuffer, error)
}

func (h *mockHelper) getUserPinCode(path string) (*secureBuffer, error) {
	return h.mockGetUserPinCode(path)
}

func (h *mockHelper) config(keyMap map[uint]*secureBuffer) loginHelper {
	h.keyMap = keyMap
	return h
}

func Test_getLoginSessions(t *testing.T) {
	type args struct {
		p11ctx *mock.MockPKCS11Ctx
		keys   []config.KeyConfig
		helper *mockHelper
	}

	defaultPathAsPinCode := func(path string) (*secureBuffer, error) {
		return newSecureBuffer([]byte(path)), nil
	}
	failedGetPinCode := func(_ string) (*secureBuffer, error) {
		return nil, errors.New("some error")
	}

	tests := []struct {
		name    string
		setup   func(t *testing.T) (*gomock.Controller, args)
		want    map[uint]p11.SessionHandle
		wantErr bool
		errMsg  map[string]error
	}{
		{
			name: "nil key",
			setup: func(t *testing.T) (*gomock.Controller, args) {
				mockCtrl := gomock.NewController(t)
				return mockCtrl, args{
					p11ctx: mock.NewMockPKCS11Ctx(mockCtrl),
					keys:   nil,
					helper: &mockHelper{
						mockGetUserPinCode: defaultPathAsPinCode,
					},
				}
			},
			want:    make(map[uint]p11.SessionHandle),
			wantErr: false,
		},
		{
			name: "one key",
			setup: func(t *testing.T) (*gomock.Controller, args) {
				mockCtrl := gomock.NewController(t)
				return mockCtrl, args{
					p11ctx: mock.NewMockPKCS11Ctx(mockCtrl),
					keys: []config.KeyConfig{
						{
							SlotNumber:  0,
							UserPinPath: "pin for slot 0",
						},
					},
					helper: &mockHelper{
						mockGetUserPinCode: defaultPathAsPinCode,
					},
				}
			},
			want: map[uint]p11.SessionHandle{
				0: p11.SessionHandle(0),
			},
			wantErr: false,
		},
		{
			name: "two keys using same slot and same pin code",
			setup: func(t *testing.T) (*gomock.Controller, args) {
				mockCtrl := gomock.NewController(t)
				return mockCtrl, args{
					p11ctx: mock.NewMockPKCS11Ctx(mockCtrl),
					keys: []config.KeyConfig{
						{
							SlotNumber:  0,
							UserPinPath: "pin for slot 0",
						},
						{
							SlotNumber:  0,
							UserPinPath: "pin for slot 0",
						},
					},
					helper: &mockHelper{
						mockGetUserPinCode: defaultPathAsPinCode,
					},
				}
			},
			want: map[uint]p11.SessionHandle{
				0: p11.SessionHandle(0),
			},
			wantErr: false,
		},
		{
			name: "multiple keys",
			setup: func(t *testing.T) (*gomock.Controller, args) {
				mockCtrl := gomock.NewController(t)
				return mockCtrl, args{
					p11ctx: mock.NewMockPKCS11Ctx(mockCtrl),
					keys: []config.KeyConfig{
						{
							SlotNumber:  0,
							UserPinPath: "pin for slot 0",
						},
						{
							SlotNumber:  1,
							UserPinPath: "pin for slot 1",
						},
					},
					helper: &mockHelper{
						mockGetUserPinCode: defaultPathAsPinCode,
					},
				}
			},
			want: map[uint]p11.SessionHandle{
				0: p11.SessionHandle(0),
				1: p11.SessionHandle(1),
			},
			wantErr: false,
		},
		{
			name: "fail to get pin code",
			setup: func(t *testing.T) (*gomock.Controller, args) {
				mockCtrl := gomock.NewController(t)
				return mockCtrl, args{
					p11ctx: mock.NewMockPKCS11Ctx(mockCtrl),
					keys: []config.KeyConfig{
						{
							SlotNumber:  0,
							UserPinPath: "pin for slot 0",
						},
					},
					helper: &mockHelper{
						mockGetUserPinCode: failedGetPinCode,
					},
				}
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "fail to open login session",
			setup: func(t *testing.T) (*gomock.Controller, args) {
				mockCtrl := gomock.NewController(t)
				return mockCtrl, args{
					p11ctx: mock.NewMockPKCS11Ctx(mockCtrl),
					keys: []config.KeyConfig{
						{
							SlotNumber:  0,
							UserPinPath: "pin for slot 0",
						},
					},
					helper: &mockHelper{
						mockGetUserPinCode: defaultPathAsPinCode,
					},
				}
			},
			want:    nil,
			wantErr: true,
			errMsg: map[string]error{
				"OpenSession": errors.New("error to open session"),
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockCtrl, args := tt.setup(t)
			defer mockCtrl.Finish()

			args.p11ctx.EXPECT().
				OpenSession(gomock.Any(), gomock.Any()).
				DoAndReturn(func(slotID uint, _ uint) (p11.SessionHandle, error) {
					return p11.SessionHandle(slotID), tt.errMsg["OpenSession"]
				}).
				AnyTimes()

			args.p11ctx.EXPECT().
				Login(gomock.Any(), p11.CKU_USER, gomock.Any()).
				Return(tt.errMsg["Login"]).
				AnyTimes()

			args.p11ctx.EXPECT().
				CloseSession(gomock.Any()).
				Return(tt.errMsg["CloseSession"]).
				AnyTimes()

			got, err := getLoginSessions(args.p11ctx, args.keys, args.helper)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, but got nil")
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("login session map is missmatched, got: %#v, want: %#v", got, tt.want)
			}

			// We store the first pin of the slot as real key.
			// If the first pin of the slot is not real, then the function will fail anyway and the
			// expected pin code in the buffer is also the first pin.
			keyMap := make(map[uint]string)
			for _, key := range args.keys {
				if _, exist := keyMap[key.SlotNumber]; !exist {
					keyMap[key.SlotNumber] = key.UserPinPath
				}
			}

			// Check if the pin code stores in the secure buffer is cleaned.
			for slot := range args.helper.keyMap {
				if buffer, exist := args.helper.keyMap[slot]; !exist {
					t.Errorf("the pin buffer for slot #%d is missing", slot)
				} else if buffer.get() == keyMap[slot] {
					t.Errorf("the pin buffer for slot #%d is not cleaned", slot)
				} else {
					t.Logf("%v\n%v\n", buffer, keyMap[slot])
				}
			}
		})
	}
}
