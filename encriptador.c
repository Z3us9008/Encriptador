#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define TAMANO_CLAVE 32
#define TAMANO_IV 16

void manejarErrores(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int encriptar(FILE *entrada, FILE *salida, unsigned char *clave, unsigned char *iv) {
    EVP_CIPHER_CTX *ctx;
    int longitud;
    int longitud_cifrado;
    unsigned char buffer_entrada[1024];
    unsigned char buffer_salida[1024 + EVP_MAX_BLOCK_LENGTH];

    if (!(ctx = EVP_CIPHER_CTX_new())) manejarErrores();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, clave, iv))
        manejarErrores();

    while (1) {
        int longitud_entrada = fread(buffer_entrada, 1, 1024, entrada);
        if (longitud_entrada <= 0) break;

        if (1 != EVP_EncryptUpdate(ctx, buffer_salida, &longitud, buffer_entrada, longitud_entrada))
            manejarErrores();
        fwrite(buffer_salida, 1, longitud, salida);
    }

    if (1 != EVP_EncryptFinal_ex(ctx, buffer_salida, &longitud)) manejarErrores();
    fwrite(buffer_salida, 1, longitud, salida);

    longitud_cifrado = ftell(salida);

    EVP_CIPHER_CTX_free(ctx);

    return longitud_cifrado;
}

int desencriptar(FILE *entrada, FILE *salida, unsigned char *clave, unsigned char *iv) {
    EVP_CIPHER_CTX *ctx;
    int longitud;
    int longitud_descifrado;
    unsigned char buffer_entrada[1024 + EVP_MAX_BLOCK_LENGTH];
    unsigned char buffer_salida[1024];

    if (!(ctx = EVP_CIPHER_CTX_new())) manejarErrores();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, clave, iv))
        manejarErrores();

    while (1) {
        int longitud_entrada = fread(buffer_entrada, 1, 1024, entrada);
        if (longitud_entrada <= 0) break;

        if (1 != EVP_DecryptUpdate(ctx, buffer_salida, &longitud, buffer_entrada, longitud_entrada))
            manejarErrores();
        fwrite(buffer_salida, 1, longitud, salida);
    }

    if (1 != EVP_DecryptFinal_ex(ctx, buffer_salida, &longitud)) manejarErrores();
    fwrite(buffer_salida, 1, longitud, salida);

    longitud_descifrado = ftell(salida);

    EVP_CIPHER_CTX_free(ctx);

    return longitud_descifrado;
}

void menu() {
    printf("\nMenú:\n");
    printf("1. Encriptar un archivo\n");
    printf("2. Desencriptar un archivo\n");
    printf("3. Salir\n");
    printf("Seleccione una opción: ");
}

void encriptarArchivo() {
    char archivoEntrada[256], archivoSalida[256], contrasena[256];

    printf("Ingrese el nombre del archivo de entrada: ");
    scanf("%s", archivoEntrada);
    printf("Ingrese el nombre del archivo de salida: ");
    scanf("%s", archivoSalida);
    printf("Ingrese la contraseña: ");
    scanf("%s", contrasena);

    FILE *entrada = fopen(archivoEntrada, "rb");
    if (!entrada) {
        perror("fopen");
        return;
    }

    FILE *salida = fopen(archivoSalida, "wb");
    if (!salida) {
        perror("fopen");
        fclose(entrada);
        return;
    }

    unsigned char clave[TAMANO_CLAVE];
    unsigned char iv[TAMANO_IV];

    if (!PKCS5_PBKDF2_HMAC(contrasena, strlen(contrasena), NULL, 0, 10000, EVP_sha256(), TAMANO_CLAVE, clave)) {
        fprintf(stderr, "Error derivando la clave\n");
        fclose(entrada);
        fclose(salida);
        return;
    }

    if (!RAND_bytes(iv, TAMANO_IV)) {
        fprintf(stderr, "Error generando el IV\n");
        fclose(entrada);
        fclose(salida);
        return;
    }

    fwrite(iv, 1, TAMANO_IV, salida);
    encriptar(entrada, salida, clave, iv);

    printf("Archivo encriptado exitosamente.\n");

    fclose(entrada);
    fclose(salida);
}

void desencriptarArchivo() {
    char archivoEntrada[256], archivoSalida[256], contrasena[256];

    printf("Ingrese el nombre del archivo de entrada: ");
    scanf("%s", archivoEntrada);
    printf("Ingrese el nombre del archivo de salida: ");
    scanf("%s", archivoSalida);
    printf("Ingrese la contraseña: ");
    scanf("%s", contrasena);

    FILE *entrada = fopen(archivoEntrada, "rb");
    if (!entrada) {
        perror("fopen");
        return;
    }

    FILE *salida = fopen(archivoSalida, "wb");
    if (!salida) {
        perror("fopen");
        fclose(entrada);
        return;
    }

    unsigned char clave[TAMANO_CLAVE];
    unsigned char iv[TAMANO_IV];

    if (!PKCS5_PBKDF2_HMAC(contrasena, strlen(contrasena), NULL, 0, 10000, EVP_sha256(), TAMANO_CLAVE, clave)) {
        fprintf(stderr, "Error derivando la clave\n");
        fclose(entrada);
        fclose(salida);
        return;
    }

    fread(iv, 1, TAMANO_IV, entrada);
    desencriptar(entrada, salida, clave, iv);

    printf("Archivo desencriptado exitosamente.\n");

    fclose(entrada);
    fclose(salida);
}

int main() {
    while (1) {
        int opcion;
        menu();
        scanf("%d", &opcion);

        switch (opcion) {
            case 1:
                encriptarArchivo();
                break;
            case 2:
                desencriptarArchivo();
                break;
            case 3:
                printf("Saliendo...\n");
                return 0;
            default:
                printf("Opción no válida. Intente nuevamente.\n");
        }
    }
    return 0;
}
