package http_test

import (
	p "github.com/DMA8/authService/internal/adapters/http"
	"github.com/DMA8/authService/internal/domain/models"
	"context"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWriteAnswer(t *testing.T) {
	w := &httptest.ResponseRecorder{}
	statusTest := 200
	stringTest := "test"
	p.WriteAnswer(w, statusTest, stringTest)
	assert.Equal(t, statusTest, w.Result().StatusCode)
}

func TestGetReqID(t *testing.T){
	ctx := context.WithValue(context.Background(), p.RidKey, "test")
	res := p.GetReqID(ctx)
	assert.Equal(t, res, "test")
}


func TestSetCookie(t *testing.T) {
	w := &httptest.ResponseRecorder{}
	testCookieName := "test"
	testToken := "testToken"
	testPath := "/testPath"
	p.SetCookie(w, testCookieName, testToken, testPath)
	cookies := w.Result().Cookies()
	assert.Equal(t, testCookieName, cookies[0].Name)
	assert.Equal(t, testToken, cookies[0].Value)
}

func Test_getCookieValue(t *testing.T) {
	type args struct {
		cookies []string
	}
	test1Res := make(map[string]string)
	test1Res["access"] = "1234"
	test1Res["refresh"] = "4321"

	tests := []struct {
		name    string
		args    args
		want    map[string]string
		wantErr bool
	}{
		{
			name:    "test1",
			args:    args{[]string{"access=1234", "refresh=4321"}},
			want:    test1Res,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := p.GetCookieValue(tt.args.cookies)
			if (err != nil) != tt.wantErr {
				t.Errorf("getCookieValue() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getCookieValue() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetCredsFromCtx(t *testing.T) {
	t1 := &models.Credentials{Login: "admin", Password: "123"}
	ctx := context.WithValue(context.Background(), p.CrudCreds, t1)
	creds, err := p.GetCredsFromCtx(ctx)
	assert.NoError(t, err)
	assert.Equal(t, creds, t1)
}
