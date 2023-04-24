package main

import (
	"io"
	"net/http"
	"reflect"
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

func includes(arr []string, value string) bool {
	for _, v := range arr {
		if v == value {
			return true
		}
	}
	return false
}

func copyHeader(target http.Header, origin http.Header, keys []string) {
	for key := range origin {
		if includes(keys, key) {
			target.Set(key, origin.Get(key))
		}
	}
}
