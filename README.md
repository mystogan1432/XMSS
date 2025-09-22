# XMSS
Implementation of the post-quantum secure hash function XMSS in python. Also, a simple fault attack.<br />
Information on the scheme: https://www.rfc-editor.org/rfc/rfc8391.html<br />
To prove that the root is correct, follow the authentication path by hashing the signature and then following the path.<br />
  "r" tag means that hash value should be concatenated on the right<br />
  "l" tag means that hash values should be concatenated on the left.<br />
modify "depth" to find a longer partial hash collision<br />
  --Warning: will take longer--
