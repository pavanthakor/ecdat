"""must_fire: py-hashlib-md5 -- both the attribute and the string-arg form."""
import hashlib

digest = hashlib.md5(b"payload").hexdigest()
other = hashlib.new("md5", b"payload").hexdigest()
