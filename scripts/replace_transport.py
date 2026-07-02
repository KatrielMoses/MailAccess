with open(r'C:\MailAccess\tests\test_employee_name_discovery_module.py','r',encoding='utf-8') as f:
    content = f.read()

old = (
    '    transport = httpx.AsyncClient(\n'
    '        transport=httpx.MockTransport(\n'
    '            lambda request: httpx.Response(200, text="<html></html>")\n'
    '        ),\n'
    '        timeout=2.0,\n'
    '    )\n'
    '    monkeypatch.setattr(\n'
    '        "backend.modules.employee_name_discovery.build_client",\n'
    '        lambda *a, **kw: transport,\n'
    '    )'
)
new = (
    '    def _make_transport():\n'
    '        return httpx.AsyncClient(\n'
    '            transport=httpx.MockTransport(\n'
    '                lambda request: httpx.Response(200, text="<html></html>")\n'
    '            ),\n'
    '            timeout=2.0,\n'
    '        )\n\n'
    '    monkeypatch.setattr(\n'
    '        "backend.modules.employee_name_discovery.build_client",\n'
    '        _make_transport,\n'
    '    )'
)
count = content.count(old)
content = content.replace(old, new)
with open(r'C:\MailAccess\tests\test_employee_name_discovery_module.py','w',encoding='utf-8') as f:
    f.write(content)
print(f'Replaced {count} occurrences')
