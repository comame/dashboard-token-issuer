package main

import (
	"os"
	"reflect"
)

func readenv(s interface{}) {
	v := reflect.ValueOf(s)
	if v.Kind() != reflect.Pointer {
		panic("ポインタでない")
	}

	elem := v.Elem()
	if elem.Kind() != reflect.Struct {
		panic("構造体でない")
	}

	for i := 0; i < elem.NumField(); i += 1 {
		fieldValue := elem.Field(i)
		fieldType := elem.Type().Field(i)

		if fieldValue.Kind() != reflect.String {
			panic("フィールドが string でない")
		}

		envname := fieldType.Tag.Get("env")
		if envname == "" {
			panic("環境変数名が未指定")
		}

		env, ok := os.LookupEnv(envname)
		if !ok {
			panic("環境変数がない: " + envname)
		}

		fieldValue.Set(reflect.ValueOf(env))
	}
}
