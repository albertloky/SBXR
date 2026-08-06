package state

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
)

var errProtectedValueRendering = errors.New("protected value cannot be rendered")

func marshalProtectedJSON(value any) ([]byte, error) {
	plain, err := protectedJSONValue(reflect.ValueOf(value))
	if err != nil {
		return nil, err
	}
	return json.Marshal(plain)
}

func protectedJSONValue(value reflect.Value) (any, error) {
	if !value.IsValid() {
		return nil, nil
	}
	if value.Kind() == reflect.Interface {
		return protectedJSONValue(value.Elem())
	}
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return nil, nil
		}
		return protectedJSONValue(value.Elem())
	}
	if value.CanInterface() {
		switch protected := value.Interface().(type) {
		case ClientAccessValue:
			return protected.value, nil
		case InfrastructureSecret:
			return protected.value, nil
		}
	}
	switch value.Kind() {
	case reflect.Struct:
		object := map[string]any{}
		valueType := value.Type()
		for index := range value.NumField() {
			field := valueType.Field(index)
			if !field.IsExported() {
				continue
			}
			tag := strings.Split(field.Tag.Get("json"), ",")
			if tag[0] == "-" {
				continue
			}
			name := tag[0]
			if name == "" {
				name = field.Name
			}
			fieldValue := value.Field(index)
			if len(tag) > 1 && tag[1] == "omitempty" && fieldValue.IsZero() {
				continue
			}
			plain, err := protectedJSONValue(fieldValue)
			if err != nil {
				return nil, err
			}
			object[name] = plain
		}
		return object, nil
	case reflect.Slice, reflect.Array:
		array := make([]any, value.Len())
		for index := range value.Len() {
			plain, err := protectedJSONValue(value.Index(index))
			if err != nil {
				return nil, err
			}
			array[index] = plain
		}
		return array, nil
	default:
		if value.CanInterface() {
			return value.Interface(), nil
		}
		return nil, errors.New("unsupported protected JSON value")
	}
}
