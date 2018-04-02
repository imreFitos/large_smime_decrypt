/* 
 decrypt smime AES encrypted DER binary files that are larger than 1.5GB
 by Imre Fitos 2018
 based on Dr Stephen N. Henson's suggestion from 2011
 to work around the malloc failure
 https://groups.google.com/forum/#!topic/mailing.openssl.users/xCxyJyEgjGU
*/

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>


int main (int argc, char *argv[])
{
  struct stat sb;
  off_t len;
  const unsigned char *p;
  int fd;

  BIO *in = NULL, *privbio = NULL;
  BIO *out = BIO_new_fp(stdout, BIO_NOCLOSE);
  EVP_PKEY *rkey = NULL;
  PKCS7 *p7 = NULL;
  int ret = 1;

  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  if (argc != 3) {
    fprintf (stderr, "usage: %s <privkey> <infile> > outfile\n", argv[0]);
    return 1;
  }

  /* read private key */
  privbio = BIO_new_file(argv[1], "r");

  if (!privbio)
    goto err;

  fprintf(stderr, "About to read priv key\n");
  rkey = PEM_read_bio_PrivateKey(privbio, NULL, 0, NULL);

  /* read file to decrypt */
  fd = open (argv[2], O_RDONLY);
  if (fd == -1) {
    perror ("open");
    return 1;
  }

  if (fstat (fd, &sb) == -1) {
    perror ("fstat");
    return 1;
  }

  if (!S_ISREG (sb.st_mode)) {
    fprintf (stderr, "%s is not a file\n", argv[3]);
    return 1;
  }

  p = mmap (0, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
  if (p == MAP_FAILED) {
    perror ("mmap");
    return 1;
  }

  if (close (fd) == -1) {
    perror ("close");
    return 1;
  }

  in = BIO_new_mem_buf(p, sb.st_size);

  if (!in)
    goto err;

  /* open file the old way - runs out of memory
  fprintf(stderr, "About to open encrypted file\n");
  in = BIO_new_file(argv[3], "r");

  if (!in)
    goto err;
  */

  fprintf(stderr, "About to read encrypted file\n");
  p7 = d2i_PKCS7(NULL, &p, sb.st_size);

  if (!p7)
    goto err;

  /* for (len = 0; len < sb.st_size; len++)
    putchar (p[len]);
  */

  fprintf(stderr, "About to decrypt encrypted file\n");
  if (!PKCS7_decrypt(p7, rkey, NULL, out, 0))
    goto err;

  if (munmap ((char *) p, sb.st_size) == -1) {
    perror ("munmap");
    return 1;
  }

  return 0;

  err:
    if (ret) {
        fprintf(stderr, "EROR:\n");
        ERR_print_errors_fp(stderr);
    }
    PKCS7_free(p7);
    EVP_PKEY_free(rkey);
    BIO_free(in);
    BIO_free(out);
    BIO_free(privbio);

    return ret;

}
