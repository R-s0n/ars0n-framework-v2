package utils

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
)

// Loading a tool config whose numbers do not match the struct.
//
// encoding/json refuses to put 1.67 into an int field. It reports an error and leaves that one
// field at its zero value, and every call site in this repo ignores the error, so the symptom is
// not a failure: it is a setting that silently becomes 0. For a rate limit expressed as a delay,
// zero means no delay, which is the opposite of what was asked for.
//
// That is not hypothetical. The Target Behaviour Probe used to write arjun and x8 delays as rounded
// floats, so applying a measured rate wrote 1.67 into an int column and the tool then ran with no
// pacing at all while the UI reported the rate as applied. The translation is fixed, but configs
// written before that fix are still in the database, and the config GET handlers return 500 on the
// unmarshal error, which locks the operator out of the very modal they would use to correct it.
//
// So loading is made tolerant rather than strict. A number that cannot be an int is rounded to the
// nearest one, which is the value the operator meant, and the config opens.

// UnmarshalConfigTolerant decodes JSON into a struct, rounding any fractional number that lands in
// an integer field instead of discarding it.
//
// The fast path is a plain Unmarshal. The repair only runs when that fails, so a healthy config
// costs nothing.
func UnmarshalConfigTolerant(data []byte, out interface{}) error {
	if len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err == nil {
		return nil
	}

	var loose map[string]interface{}
	if err := json.Unmarshal(data, &loose); err != nil {
		// Not an object at all, so there is nothing to repair. Report the original problem.
		return json.Unmarshal(data, out)
	}

	coerceIntFields(reflect.TypeOf(out), loose)

	repaired, err := json.Marshal(loose)
	if err != nil {
		return err
	}
	return json.Unmarshal(repaired, out)
}

// coerceIntFields walks a struct type and rounds any float sitting in a field that wants an integer.
//
// Driven by the struct rather than by guessing from the value, because a float that happens to be
// whole is fine where a float is wanted, and rounding it there would quietly change a rate of 2.5
// requests per second into 2.
func coerceIntFields(t reflect.Type, values map[string]interface{}) {
	for t != nil && t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t == nil || t.Kind() != reflect.Struct {
		return
	}

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		name := jsonFieldName(field)
		if name == "" {
			continue
		}
		raw, present := values[name]
		if !present || raw == nil {
			continue
		}

		ft := field.Type
		for ft.Kind() == reflect.Ptr {
			ft = ft.Elem()
		}

		switch ft.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			if f, ok := raw.(float64); ok && f != math.Trunc(f) {
				values[name] = math.Round(f)
			}
		case reflect.Struct:
			if nested, ok := raw.(map[string]interface{}); ok {
				coerceIntFields(ft, nested)
			}
		case reflect.Slice:
			items, ok := raw.([]interface{})
			if !ok {
				continue
			}
			elem := ft.Elem()
			for elem.Kind() == reflect.Ptr {
				elem = elem.Elem()
			}
			if elem.Kind() != reflect.Struct {
				continue
			}
			for _, item := range items {
				if nested, ok := item.(map[string]interface{}); ok {
					coerceIntFields(elem, nested)
				}
			}
		}
	}
}

// jsonFieldName resolves the key this field is stored under, honouring the json tag and skipping
// anything explicitly excluded.
func jsonFieldName(field reflect.StructField) string {
	tag := field.Tag.Get("json")
	if tag == "-" {
		return ""
	}
	if tag == "" {
		return field.Name
	}
	name := strings.Split(tag, ",")[0]
	if name == "" {
		return field.Name
	}
	return name
}
