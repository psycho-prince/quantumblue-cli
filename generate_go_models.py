import re
import os

schema_path = '../quantumblue-web/prisma/schema.prisma'
out_dir = 'internal/model'

with open(schema_path, 'r') as f:
    schema_content = f.read()

models = re.findall(r'model\s+(\w+)\s+\{([^}]+)\}', schema_content)

type_mapping = {
    'String': 'string',
    'String?': '*string',
    'Int': 'int',
    'Int?': '*int',
    'Float': 'float64',
    'Float?': '*float64',
    'Boolean': 'bool',
    'Boolean?': '*bool',
    'DateTime': 'time.Time',
    'DateTime?': '*time.Time',
    'Json': 'json.RawMessage',
    'Json?': 'json.RawMessage',
    'String[]': '[]string',
}

os.makedirs(out_dir, exist_ok=True)

for model_name, body in models:
    fields = []
    lines = body.strip().split('\n')
    has_time = False
    has_json = False
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('//') or line.startswith('@@'):
            continue
        parts = re.split(r'\s+', line)
        if len(parts) < 2:
            continue
            
        field_name = parts[0]
        field_type = parts[1]
        
        # skip relation fields (assuming they start with uppercase or are arrays of relations)
        if field_type.startswith(tuple('ABCDEFGHIJKLMNOPQRSTUVWXYZ')) and not field_type in ['String', 'Int', 'Float', 'Boolean', 'DateTime', 'Json']:
            continue
        if field_type.endswith('[]') and field_type[:-2].startswith(tuple('ABCDEFGHIJKLMNOPQRSTUVWXYZ')) and field_type[:-2] != 'String':
            continue
            
        go_type = type_mapping.get(field_type, 'string') # fallback
        if 'time.Time' in go_type:
            has_time = True
        if 'json.RawMessage' in go_type:
            has_json = True
            
        go_field_name = field_name[0].upper() + field_name[1:]
        
        fields.append(f'    {go_field_name} {go_type} `json:"{field_name}" db:"{field_name}"`')

    # write go file
    file_content = f"package model\n\nimport (\n"
    if has_json:
        file_content += '    "encoding/json"\n'
    if has_time:
        file_content += '    "time"\n'
    file_content += ")\n\n"
    
    file_content += f"type {model_name} struct {{\n"
    file_content += "\n".join(fields)
    file_content += "\n}\n"
    
    file_name = f"{out_dir}/{model_name.lower()}.go"
    with open(file_name, 'w') as f:
        f.write(file_content)

    # write test file
    test_file_content = f"""package model

import (
    "encoding/json"
    "testing"
)

func Test{model_name}RoundTrip(t *testing.T) {{
    var obj {model_name}
    data := []byte(`{{}}`) // minimal valid json for round trip
    if err := json.Unmarshal(data, &obj); err != nil {{
        t.Fatalf("Failed to unmarshal {model_name}: %v", err)
    }}
    if _, err := json.Marshal(obj); err != nil {{
        t.Fatalf("Failed to marshal {model_name}: %v", err)
    }}
}}
"""
    test_file_name = f"{out_dir}/{model_name.lower()}_test.go"
    with open(test_file_name, 'w') as f:
        f.write(test_file_content)

print("Go models generated.")
