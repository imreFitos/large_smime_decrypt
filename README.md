
openssl smime decrypt fails with the following error message when decrypting big files larger than 1.5GB:

> Error reading S/MIME message
> 140735793181576:error:07069041:memory buffer routines:BUF_MEM_grow_clean:malloc failure:buffer.c:150:
> 140735793181576:error:0D06B041:asn1 encoding routines:ASN1_D2I_READ_BIO:malloc failure:a_d2i_fp.c:239:

large_smime_decrypt uses a memory mapped file to go around the BIO_new_file limitation.

By Imre Fitos 2018
