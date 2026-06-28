# GMP bridge

Converte achados → report XML e importa no **gvmd** para aparecerem na GSA. Implementa o `ResultSink`
(ver [ADR-0002](../docs/adr/0002-destino-dos-resultados.md)).

Mecanismo **verificado** (python-gvm, GMP v22.x / gvmd 26.31.1):

```python
res = gmp.create_container_task(name=..., comment="...")   # "meta task to import and view reports"
task_id = res.xpath("//@id")[0]
gmp.import_report(report_xml, task_id=task_id, in_assets=True)
```

`report_xml`: `<report><report id><ports/><results><result> host/port/nvt(oid)/threat/severity/
description </result></results></report></report>`.

Em **Python** (reusa `python-gvm` diretamente). Alvo futuro do `ResultSink`: **openvasd (REST)**,
quando substituir o ospd/OSP. **Fase 2.**
