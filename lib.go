package main

import (
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
)

func requestAndGetStr(req *http.Request) (string, error) {
	res, err := new(http.Client).Do(req)
	if err != nil {
		return "", err
	}

	resStr, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	return string(resStr), nil
}

func validateIsFilled(obj interface{}) bool {
	v := reflect.ValueOf(obj)
	switch v.Kind() {
	case reflect.Struct:
		for i := 0; i < v.NumField(); i += 1 {
			child := v.FieldByIndex([]int{i})
			return validateIsFilled(child.Interface())
		}
	case reflect.String:
		raw := v.String()
		return raw != ""
	default:
		panic("unimplemented")
	}
	panic("unreachable")
}

func extractJwtPayload(jwt string) (string, error) {
	splited := strings.Split(jwt, ".")
	if len(splited) != 3 {
		return "", errors.New("Invalid_JWT_Format")
	}
	return splited[1], nil
}
