package state

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

type releaseSchema struct {
	Draft                string                   `json:"$schema,omitempty"`
	Title                string                   `json:"title,omitempty"`
	Type                 string                   `json:"type"`
	Const                any                      `json:"const,omitempty"`
	Minimum              *uint64                  `json:"minimum,omitempty"`
	MinLength            *uint64                  `json:"minLength,omitempty"`
	Pattern              string                   `json:"pattern,omitempty"`
	Properties           map[string]releaseSchema `json:"properties,omitempty"`
	Required             []string                 `json:"required,omitempty"`
	AdditionalProperties *bool                    `json:"additionalProperties,omitempty"`
}

func ReleaseDefinitions() (map[string][]byte, error) {
	one := uint64(1)
	noExtras := false
	schemaFor := func(version uint64) releaseSchema {
		return releaseSchema{
			Draft: "https://json-schema.org/draft/2020-12/schema", Title: "SBXR Desired State v" + fmt.Sprint(version), Type: "object", AdditionalProperties: &noExtras,
			Properties: map[string]releaseSchema{
				"schema_version":            {Type: "integer", Const: version},
				"revision":                  {Type: "integer", Minimum: &one},
				"release_identity":          releaseSchemaFor(reflect.TypeOf(ReleaseIdentity{})),
				"last_completed_change_set": {Type: "string", MinLength: &one},
				"payload":                   releaseSchemaFor(reflect.TypeOf(DesiredState{})),
				"checksum":                  {Type: "string", Pattern: "^[0-9a-f]{64}$"},
			},
			Required: []string{"schema_version", "revision", "release_identity", "last_completed_change_set", "payload", "checksum"},
		}
	}
	v1Schema := schemaFor(1)
	payload := v1Schema.Properties["payload"]
	delete(payload.Properties, "reclamation")
	v1Schema.Properties["payload"] = payload
	certificates := v1Schema.Properties["payload"].Properties["certificates"]
	delete(certificates.Properties, "owner_email")
	v1, err := json.Marshal(v1Schema)
	if err != nil {
		return nil, err
	}
	v2, err := json.Marshal(schemaFor(2))
	if err != nil {
		return nil, err
	}
	return map[string][]byte{"desired-state-v1.schema.json": v1, "desired-state-v2.schema.json": v2}, nil
}

func ReleaseMigrations() map[string][]byte {
	return map[string][]byte{"state-v1-to-v2.json": []byte(`{"schema":1,"from":1,"to":2,"operations":[{"op":"replace","path":"/schema_version","value":2}]}`)}
}

func releaseSchemaFor(valueType reflect.Type) releaseSchema {
	zero, one := uint64(0), uint64(1)
	if valueType == reflect.TypeOf(ClientAccessValue{}) || valueType == reflect.TypeOf(InfrastructureSecret{}) {
		return releaseSchema{Type: "string", MinLength: &one}
	}
	switch valueType.Kind() {
	case reflect.Bool:
		return releaseSchema{Type: "boolean"}
	case reflect.String:
		return releaseSchema{Type: "string"}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return releaseSchema{Type: "integer", Minimum: &zero}
	case reflect.Struct:
		noExtras := false
		schema := releaseSchema{Type: "object", Properties: map[string]releaseSchema{}, AdditionalProperties: &noExtras}
		for index := range valueType.NumField() {
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
			schema.Properties[name] = releaseSchemaFor(field.Type)
			if len(tag) == 1 || tag[1] != "omitempty" {
				schema.Required = append(schema.Required, name)
			}
		}
		return schema
	default:
		return releaseSchema{}
	}
}
