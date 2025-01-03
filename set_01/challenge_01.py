import base64

hex_str = bytes.fromhex("49276d206b696c6c696e6720796f7572206272616"
                        "96e206c696b65206120706f69736f6e6f7573206d"
                        "757368726f6f6d")
target_str = b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsa"
target_str += b"WtlIGEgcG9pc29ub3VzIG11c2hyb29t"
encoded_str = base64.b64encode(hex_str)

assert encoded_str == target_str

print("Test Passed!")
