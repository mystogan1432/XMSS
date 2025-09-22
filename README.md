# XMSS
Implementation of the post-quantum secure hash function XMSS in python. Also, a simple fault attack.
Information on the scheme: https://www.rfc-editor.org/rfc/rfc8391.html
To prove that the root is correct, follow the authentication path by hashing the signature and then following the path.
  "r" tag means that hash value should be concatenated on the right
  "l" tag means that hash values should be concatenated on the left.
modify "depth" to find a longer partial hash collision
  --Warning: will take longer--
