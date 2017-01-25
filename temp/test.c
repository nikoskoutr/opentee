#include <openssl/evp.h>
#include <stdint.h>
int main(){
// const EVP_MD *hash = NULL;
uint32_t r = (uint32_t) EVP_MD_size(EVP_sha1());
printf("%d", r);
}
