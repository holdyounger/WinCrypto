
typedef unsigned int ARCH_WORD_32;

void PBKDF2_DCC2_plug(const unsigned char* pass, const unsigned char* salt, int saltlen, ARCH_WORD_32* out, int idx);

int dcc2_tst(int argc, char** argv);