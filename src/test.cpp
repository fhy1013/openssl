#include <openssl/md5.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <stdio.h>
#include <string.h>
#include <iostream>

using namespace std;

#define PUBLICKEY "publicKey.pem"
#define PRIVATEKEY "privateKey.pem"

#define PASS "8888"  // 口令

void md5() {
  MD5_CTX ctx;
  unsigned char outmd[16];
  memset(outmd, 0, sizeof(outmd));
  MD5_Init(&ctx);
  MD5_Update(&ctx, "hel", 3);
  MD5_Update(&ctx, "lo\n", 3);
  MD5_Final(outmd, &ctx);
  for (int i = 0; i < 16; i++) {
    printf("%02X", outmd[i]);
  }
  printf("\n");
  return;
}

void RSAWithFileKey() {
  FILE *fp = NULL;
  RSA *publicRsa = RSA_new();
  RSA *privateRsa = RSA_new();

  if ((fp = fopen(PUBLICKEY, "r")) == NULL) {
    printf("public key path error\n");
    return;
  }
  if ((PEM_read_RSA_PUBKEY(fp, &publicRsa, NULL, NULL)) == NULL) {
    printf("PEM_read_RSA_PUBKEY error\n");
    return;
  }
  fclose(fp);

  if ((fp = fopen(PRIVATEKEY, "r")) == NULL) {
    printf("private key path error\n");
    return;
  }
  //	OpenSSL_add_all_algorithms();  //密钥有经过口令加密需要这个函数
  //	if ((privateRsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, (char *)PASS))
  //== 		NULL) {
  if (PEM_read_RSAPrivateKey(fp, &privateRsa, NULL, NULL) == NULL) {
    printf("PEM_read_RSAPrivateKey error\n");
    return;
  }
  fclose(fp);

  unsigned char *source = (unsigned char *)"123456789";
  const std::string str =
      "sdfasdfsldkjeisrowe cjio ivvir rir iire9235320v4890v94tm0v34";

  int rsa_len = RSA_size(publicRsa);

  unsigned char *encryptMsg = (unsigned char *)malloc(rsa_len);
  memset(encryptMsg, 0, rsa_len);

  int len = rsa_len - 11;

  if (RSA_public_encrypt(len, (const unsigned char *)str.c_str(), encryptMsg,
                         publicRsa, RSA_PKCS1_PADDING) < 0)
    printf("RSA_public_encrypt error\n");
  else {
    rsa_len = RSA_size(privateRsa);
    unsigned char *decryptMsg = (unsigned char *)malloc(rsa_len);
    memset(decryptMsg, 0, rsa_len);

    int mun = RSA_private_decrypt(rsa_len, encryptMsg, decryptMsg, privateRsa,
                                  RSA_PKCS1_PADDING);

    if (mun < 0)
      printf("RSA_private_decrypt error\n");
    else
      printf("RSA_private_decrypt [%s]\n", decryptMsg);
  }
  RSA_free(publicRsa);
  RSA_free(privateRsa);

  return;
}

std::string EncodeRSAKeyFile(const std::string &pem_file,
                             const std::string &data) {
  std::string ret = "";
  if (pem_file.empty() || data.empty()) {
    return ret;
  }
  FILE *fp_key = fopen(pem_file.c_str(), "rb");
  if (fp_key == nullptr) {
    return ret;
  }

  RSA *prsa_public_key = RSA_new();
  if (PEM_read_RSA_PUBKEY(fp_key, &prsa_public_key, nullptr, nullptr) ==
      nullptr) {
    fclose(fp_key);
    return ret;
  }
  fclose(fp_key);

  int rsa_len = RSA_size(prsa_public_key);

  char *pencode = new char[rsa_len + 1];
  int nRet = RSA_public_encrypt(
      data.length(), (const unsigned char *)data.c_str(),
      (unsigned char *)pencode, prsa_public_key, RSA_PKCS1_PADDING);
  if (nRet >= 0) {
    ret = std::string(pencode, nRet);
  }
  delete[] pencode;
  RSA_free(prsa_public_key);
  CRYPTO_cleanup_all_ex_data();

  return ret;
}

std::string DencodeRSAKeyFile(const std::string &pem_file,
                              const std::string &data) {
  std::string ret = "";
  if (pem_file.empty() || data.empty()) {
    return ret;
  }
  FILE *fp_key = fopen(pem_file.c_str(), "rb");
  if (fp_key == nullptr) {
    return ret;
  }

  RSA *prsa_private_key = RSA_new();
  if (PEM_read_RSAPrivateKey(fp_key, &prsa_private_key, nullptr, nullptr) ==
      nullptr) {
    fclose(fp_key);
    return ret;
  }
  fclose(fp_key);

  int rsa_len = RSA_size(prsa_private_key);

  char *pencode = new char[rsa_len + 1];
  int nRet = RSA_private_decrypt(
      data.length(), (const unsigned char *)data.c_str(),
      (unsigned char *)pencode, prsa_private_key, RSA_PKCS1_PADDING);
  if (nRet >= 0) {
    ret = std::string(pencode, nRet);
  }
  delete[] pencode;
  RSA_free(prsa_private_key);
  CRYPTO_cleanup_all_ex_data();

  return ret;
}

void RSAWithFileKeyFunction() {
  const std::string str =
      "sdfasdfsldkjeisrowe cjio ivvir rir iire9235320v4890v94tm0v34";
  cout << "str: [" << str << "]" << endl;
  string str_encode = EncodeRSAKeyFile(PUBLICKEY, str);
  cout << "str_encode: [" << str_encode << "]" << endl;
  string str_decode = DencodeRSAKeyFile(PRIVATEKEY, str_encode);
  cout << "str_decode: [" << str_decode << "]" << endl;
  return;
}

int main() {
  cout << "test ..." << endl;
  //   md5();
  // RSAWithFileKey();
  RSAWithFileKeyFunction();

  return 0;
}
