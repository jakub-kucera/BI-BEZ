EDB:\
After encrypting an image with ECB mode, you can really see, that every block is directly encrypted, co when \
encrypting identical blocks, you get the same output. In pictures with large areas with the same color are transformed \
into the "same" large areas with a different color/pattern.
CBC:\
Encryption with CBC mode uses the value of previous encrypted value, results in the encrypted image look like random noise.