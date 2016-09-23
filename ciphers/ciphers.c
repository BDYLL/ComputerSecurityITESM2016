#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#define SHIFT_ALPHABET 97
#define ALPHABET_SIZE 26

char *caesar(char *key, char * plaintext){
	char cKey=key[0]-SHIFT_ALPHABET;
	int i;
	int plainTextLength=strlen(plaintext);
	char *result=(char*)malloc((plainTextLength+1)*sizeof(char));
	assert(result!=NULL && "cannot allocate result string");
	char tmp;
	for(i=0;i<plainTextLength;i++){
		tmp=(plaintext[i]-SHIFT_ALPHABET+cKey)%ALPHABET_SIZE+SHIFT_ALPHABET;
		result[i]=tmp;
	}
	result[plainTextLength]='\0';
	return result;
}

char *decrypt_caesar(char *key , char *plaintext){
	int cKey=(int)key[0]-SHIFT_ALPHABET;
	int i;
	int plainTextLength=strlen(plaintext);
	char *result=(char*)malloc((plainTextLength+1)*sizeof(char));
	assert(result!=NULL && "cannot allocate result string");
	int tmp;
	for(i=0;i<plainTextLength;i++){
		tmp=((int)plaintext[i]-SHIFT_ALPHABET-cKey)%ALPHABET_SIZE;
		tmp=(tmp<0) ? tmp+ALPHABET_SIZE: tmp;
		tmp+=SHIFT_ALPHABET;
		result[i]=tmp;
	}
	result[plainTextLength]='\0';
	return result;	
}

char *generate_vigenere_key(char *key, int plainTextLength){
	char *result=(char*)calloc((plainTextLength+1),sizeof(char));
	assert(result!=NULL && "cannot allocate string");
	int keyLength=strlen(key);
	int i;
	assert(result!=NULL && "cannot allocate result string");
	for(i=0;i<plainTextLength;i++){
		result[i]=key[i%keyLength];
	}	
	result[plainTextLength]='\0';
	return result;
}

char *vigenere(char *key, char *plaintext){
	int plainTextLength=strlen(plaintext);
	char *vigenere_key=generate_vigenere_key(key,plainTextLength);
	char *result=(char*)malloc((plainTextLength+1)*sizeof(char));
	assert(result!=NULL && "cannot allocate result string");
	int i;
	for(i=0;i<plainTextLength;i++){
		result[i]=(plaintext[i]+vigenere_key[i]-2*SHIFT_ALPHABET)%ALPHABET_SIZE+SHIFT_ALPHABET;
	}
	free(vigenere_key);
	result[plainTextLength]='\0';
	return result;
}

char *decrypt_vigenere(char *key, char *plaintext){
	int plainTextLength=strlen(plaintext);
	char *vigenere_key=generate_vigenere_key(key,plainTextLength);
	char *result=(char*)malloc((plainTextLength+1)*sizeof(char));
	assert(result!=NULL && "cannot allocate result string");
	int i,tmp;
	for(i=0;i<plainTextLength;i++){
		tmp=((int)plaintext[i]-(int)vigenere_key[i])%ALPHABET_SIZE;
		tmp=(tmp<0) ? tmp+ALPHABET_SIZE: tmp;
		tmp+=SHIFT_ALPHABET;
		result[i]=(char)tmp;
	}
	free(vigenere_key);
	result[plainTextLength]='\0';
	return result;	
}


char* decrypt(char *key, char *plaintext, char*(*algorithm)(char*, char*)){
	return algorithm(key, plaintext);
}

char* encrypt(char *key, char *plaintext, char*(*algorithm)(char*, char*)){
	return algorithm(key, plaintext);
}

int ignored_character(char c){
	return c<'a' || c>'z';
}

char** caesar_brute_force(char *cipher_text){

	char key[2]={'a','\0'};

	char **possible_strings=(char**)calloc(ALPHABET_SIZE,sizeof(char*));

	int i;

	for(i=0;i<ALPHABET_SIZE;i++){
		possible_strings[i]=decrypt(key,cipher_text,decrypt_caesar);
		key[0]++;
	}
	return possible_strings;
}

char* read_file(char *path){
	FILE *f=fopen(path,"r");

	char *result=malloc(10*sizeof(char));
	assert(result!=NULL && "cannot allocate string");
	char cur=fgetc(f);
	int i=0;
	int cur_length=9;

	while(cur!=EOF){
		i++;
		if(i==cur_length){
			result=realloc(result,(cur_length+10)*sizeof(char));
			assert(result!=NULL && "cannot reallocate string");
			cur_length+=10;
		}
		if(!ignored_character(cur)){
			result[i-1]=cur;
		}
		else{
			i--;
		}
		cur=fgetc(f);
	}
	result[i]='\0';
	fclose(f);
	return result;	
}

int main(int argc, char **argv){

	if(argc!=2){
		printf("usage: ciphers <filepath> \n");
		exit(1);
	}

	char *plaintext=read_file(argv[1]);

	printf("Plain text to encrypt\n");
	printf("%s\n\n", plaintext);

	printf("Cipher text for caesar and vigenere ciphers\n");
	char *caesar_str=encrypt("k",plaintext,caesar);

	char *vigenere_str=encrypt("lemon",plaintext,vigenere);

	printf("%s\n", caesar_str);

	printf("%s\n", vigenere_str);

	printf("\n");

	printf("Decrypted cypher text\n");
	char *caesar_dec=decrypt("k",caesar_str,decrypt_caesar);

	char *vigenere_dec=decrypt("lemon",vigenere_str,decrypt_vigenere);

	printf("%s\n", caesar_dec);

	printf("%s\n", vigenere_dec);

	printf("\n");

	printf("Brute force caesar cipher\n");
	char **possible_strings=caesar_brute_force(caesar_str);

	int i;

	for(i=0;i<ALPHABET_SIZE;i++){
		printf("%s\n", possible_strings[i]);
		free(possible_strings[i]);
	}

	free(possible_strings);
	free(plaintext);
	free(caesar_str);
	free(vigenere_str);
	free(caesar_dec);
	free(vigenere_dec);

	return 0;
}