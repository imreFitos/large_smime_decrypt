
platform=$(shell uname -s)

large_smime_decrypt: large_smime_decrypt.c
ifeq ($(platform),Linux)
	gcc -o large_smime_decrypt large_smime_decrypt.c -L /usr/local/lib -lssl -lcrypto
else ifeq ($(platform),Darwin)
	gcc -o large_smime_decrypt large_smime_decrypt.c -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lssl -lcrypto
endif

clean: 
	$(RM) large_smime_decrypt
