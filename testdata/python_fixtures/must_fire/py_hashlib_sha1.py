"""must_fire: py-hashlib-sha1 -- both the attribute and the string-arg form."""
import hashlib

digest = hashlib.sha1(b"payload").hexdigest()
other = hashlib.new("sha1", b"payload").hexdigest()
