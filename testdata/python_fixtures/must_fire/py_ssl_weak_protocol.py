"""must_fire: py-ssl-weak-protocol -- TLS 1.0 and 1.1 pinned in code."""
import ssl

old = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
older = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
