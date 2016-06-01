package util

import (
	"reflect"
	"strconv"
	"strings"

	"github.com/oleiade/reflections"
)

// GetAllValuesByNamespace() visits all (sub)elements of an object that match given namespace
func GetAllValuesByNamespace(obj interface{}, ns []string, callback func([]string, interface{})) error {
	return getValuesByNamespace(obj, ns, []string {}, callback)
}

func getValuesByNamespace(obj interface{}, ns []string, path []string, callback func([]string, interface{})) error {
	val := reflect.Indirect(reflect.ValueOf(obj))
	if len(ns) == 0 {
		callback(path, obj)
		return nil
	}
	current := ns[0]
	switch val.Kind() {
	case reflect.Map:
		for _, k := range val.MapKeys() {
			if k.String() != current && current != "*" {
				continue
			}
			if err := getValuesByNamespace(val.MapIndex(k).Interface(), ns[1:], append(path, k.String()), callback); err != nil {
				return err
			}
		}
	case reflect.Array, reflect.Slice:
		for i := 0; i < val.Len(); i++ {
			k := strconv.Itoa(i)
			if k != current && current != "*" {
				continue
			}
			if err := getValuesByNamespace(val.Index(i).Interface(), ns[1:], append(path, k), callback); err != nil {
				return err
			}
		}
	case reflect.Struct:
		fields, err := reflections.Fields(obj)
		if err != nil {
			return err
		}
		for _, field := range fields {
			f, err := reflections.GetField(obj, field)
			if err != nil {
				return err
			}
			if field == current || current == "*" {
				if err := getValuesByNamespace(f, ns[1:], append(path, field), callback); err != nil {
					return err
				}
				continue
			}
			field, err = getJsonFieldName(obj, field)
			if err != nil {
				return err
			}
			if field != "-" && (field == current || current == "*") {
				if err := getValuesByNamespace(f, ns[1:], append(path, field), callback); err != nil {
					return err
				}
			}
		}

	default:
		callback(path, obj)
	}
	return nil
}

func getJsonFieldName(object interface{}, fieldName string) (string, error) {
	jsonTag, err := reflections.GetFieldTag(object, fieldName, "json")
	if err != nil {
		return "", err
	} else if jsonTag == "" {
		return fieldName, nil
	}
	i := strings.Index(jsonTag, ",")
	if i == -1 {
		return jsonTag, nil
	}
	if tag := jsonTag[:i]; tag == "-" {
		return "-", nil
	} else if tag == "" {
		return fieldName, nil
	} else {
		return tag, nil
	}
}
