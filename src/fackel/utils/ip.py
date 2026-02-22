import ipaddress


def is_ip(value: str) -> bool:
    """Return True when the input string is a valid IP address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
