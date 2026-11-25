from .formats import encode


def render(doc, fmt):
    if fmt == "json":
        return encode(doc)
    if doc["operation"] == "compare":
        lines = [f"compare  {doc['status']}  {doc['assurance']}"]
        lines.extend(
            f"{r['check_id']}  {', '.join(r['changes'])}  {r['before_coverage']} -> {r['after_coverage']}"
            for r in doc["changes"]
        )
        lines.extend(doc["incompatible"])
    else:
        lines = [f"assess  {doc['status']}  {doc['subject']}  {doc['scope']}  {doc['assurance']}"]
        for row in doc["checks"]:
            group = "required" if row["required"] else "optional"
            reasons = ", ".join(row["reason_codes"] + row["finding_codes"])
            lines.append(f"{row['check_id']} ({group})  {row['state']}  {reasons}")
            if reasons:
                lines.append("  " + row["guidance"])
    return ("\n".join(lines) + "\n").encode()
