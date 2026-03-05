"""Shared test helper functions — importable by all test modules."""


def shell_ok(output="", audit_id="a1"):
    return {"status": "success", "output": output, "exit_code": 0, "audit_id": audit_id}


def shell_fail(output="", exit_code=1):
    return {"status": "error", "output": output, "exit_code": exit_code, "audit_id": "a1"}


def shell_denied():
    return {"status": "denied", "output": "", "exit_code": -1, "audit_id": "a1"}
