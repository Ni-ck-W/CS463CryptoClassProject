#include <iostream>
#include <getopt.h>
#include <string>
#include <vector>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>


static const int AES_KEY_SIZE = 32; // 256 bits
static const int AES_IV_SIZE = 16;  // CBC IV Size

enum class Mode {
    STRING,
    FILE,
    LIST
};

void print_usage(const char *prog) {
  std::cerr << "Usage: " << prog << " [OPTIONS]\n\n"
            << "AES-256-CBC Encryption/Decryption CLI\n\n"
            << "Options:\n"
            << "  -e, --encrypt            Encrypt\n"
            << "  -d, --decrypt            Decrypt\n"
            << "  -m, --mode <string|file|list>\n"
            << "  -t, --text <text>        Text input (for string mode)\n"
            << "  -i, --input <file>       Input file\n"
            << "  -o, --output <file>      Output file\n"
            << "  -k, --key <password>     Password/key phrase\n"
            << "  -h, --help               Show help\n\n"
            << "Examples:\n"
            << "  Encrypt string:\n"
            << "    ./aescli -e -m string -t \"hello\" -k pass\n\n"
            << "  Encrypt file:\n"
            << "    ./aescli -e -m file -i in.bin -o out.enc -k pass\n\n"
            << "  Encrypt list:\n"
            << "    ./aescli -e -m list -i list.txt -o enc.txt -k pass\n";
}

std::vector<unsigned char> sha256_key(const std::string &password) {
    std::vector<unsigned char> key(AES_KEY_SIZE);
    SHA256(reinterpret_cast<const unsigned char *>(password.c_str()), password.size(), key.data());
    return key;
}

std::string base64_encode(const std::vector<unsigned char> &data) {
    BIO *bio, *b64;
    BUF_MEM *buffer_ptr; 

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // Ignore newlines
    
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    
    BIO_write(bio, data.data(), data.size());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &buffer_ptr);

    std::string encoded(buffer_ptr->data, buffer_ptr->length);
    BIO_free_all(bio);
    return encoded;
}
std::vector<unsigned char> base64_decode(const std::string &input) {
    BIO *bio, *b64;
    std::vector<unsigned char> buffer(input.size());

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    bio = BIO_new_mem_buf(input.data(), input.size());
    bio = BIO_push(b64, bio);

    int decoded_len = BIO_read(bio, buffer.data(), buffer.size());
    if (decoded_len < 0) decoded_len = 0;

    buffer.resize(decoded_len);
    BIO_free_all(bio);

    return buffer;
}


std::vector<unsigned char> aes_encrypt(const std::vector<unsigned char> &data, const std::vector<unsigned char> &key, std::vector<unsigned char> &iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }

    iv.resize(AES_IV_SIZE);
    if (RAND_bytes(iv.data(), AES_IV_SIZE) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to generate IV");
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize encryption");
    }

    std::vector<unsigned char> ciphertext(data.size() + AES_IV_SIZE);
    int len;
    int ciphertext_len;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, data.data(), data.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EncryptUpdate failed");
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Final encryption step failed");
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(ciphertext_len);
    return ciphertext;
}
std::vector<unsigned char> aes_decrypt(const std::vector<unsigned char> &data, const std::vector<unsigned char> &key, std::vector<unsigned char> &iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize decryption");
    }

    std::vector<unsigned char> plaintext(data.size() + AES_IV_SIZE);
    int len;
    int plaintext_len;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, data.data(), data.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("DecryptUpdate failed");
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Final decryption step failed");
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(plaintext_len);
    return plaintext;
}
std::vector<unsigned char> read_file_bytes(const std::string &filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file: " + filename);
    }
    return std::vector<unsigned char>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}
void write_file_bytes(const std::string &filename, const std::vector<unsigned char> &data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file: " + filename);
    }
    file.write(reinterpret_cast<const char *>(data.data()), data.size());
}

int main(int argc, char *argv[]) {
    bool encrypt = false;
    bool decrypt = false;
    std::string mode_str;
    std::string text;
    std::string inputFile;
    std::string outputFile;
    std::string password;

    static struct option long_options[] = {
        {"encrypt", no_argument, 0, 'e'},
        {"decrypt", no_argument, 0, 'd'},
        {"mode", required_argument, 0, 'm'},
        {"text", required_argument, 0, 't'},
        {"input", required_argument, 0, 'i'},
        {"output", required_argument, 0, 'o'},
        {"password", required_argument, 0, 'k'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    int opt;

    while ((opt = getopt_long(argc, argv, "edm:t:i:o:k:h", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'e':
                encrypt = true;
                break;
            case 'd':
                decrypt = true;
                break;
            case 'm':
                mode_str = optarg;
                break;
            case 't':
                text = optarg;
                break;
            case 'i':
                inputFile = optarg;
                break;
            case 'o':
                outputFile = optarg;
                break;
            case 'k':
                password = optarg;
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                return 0;
        }
    }
    if(encrypt == decrypt) {
        std::cerr << "Error: Must specify either --encrypt or --decrypt\n";
        print_usage(argv[0]);
        return 1;
    }
    if(mode_str.empty() || password.empty()) {
        std::cerr << "Error: Mode and password are required\n";
        print_usage(argv[0]);
        return 1;
    }

    Mode mode;
    if(mode_str == "string") {
        mode = Mode::STRING;
    } else if(mode_str == "file") {
        mode = Mode::FILE;
    } else if(mode_str == "list") {
        mode = Mode::LIST;
    } else {
        std::cerr << "Error: Invalid mode. Must be 'string', 'file', or 'list'\n";
        print_usage(argv[0]);
        return 1;
    }
    try {
        std::vector<unsigned char> key = sha256_key(password);

        if(mode == Mode::STRING) {
            if(text.empty()) {
                std::cerr << "Error: Text input is required for string mode\n";
                print_usage(argv[0]);
                return 1;
            }
            if (encrypt) {
            std::vector<unsigned char> iv;
            std::vector<unsigned char> plaintext(text.begin(), text.end());
            std::vector<unsigned char> ciphertext = aes_encrypt(plaintext, key, iv);

            std::vector<unsigned char> combined;
            combined.insert(combined.end(), iv.begin(), iv.end());
            combined.insert(combined.end(), ciphertext.begin(), ciphertext.end());

            std::cout << base64_encode(combined) << "\n";
            } else {
                std::vector<unsigned char> combined = base64_decode(text);
                if (combined.size() < AES_IV_SIZE) {
                    throw std::runtime_error("Too short input");
                }

                std::vector<unsigned char> iv(combined.begin(), combined.begin() + AES_IV_SIZE);
                std::vector<unsigned char> ciphertext(combined.begin() + AES_IV_SIZE, combined.end());

                std::vector<unsigned char> plaintext = aes_decrypt(ciphertext, key, iv);

                std::cout << std::string(plaintext.begin(), plaintext.end()) << "\n";
        }
    } // End of String mode
    else if(mode == Mode::FILE) {
        if(inputFile.empty() || outputFile.empty()) {
            std::cerr << "Error: Input and output files are required for file mode\n";
            print_usage(argv[0]);
            return 1;
        }
        if (encrypt) {
            std::vector<unsigned char> iv;
            std::vector<unsigned char> data = read_file_bytes(inputFile);
            std::vector<unsigned char> ciphertext = aes_encrypt(data, key, iv);

            std::vector<unsigned char> combined;
            combined.insert(combined.end(), iv.begin(), iv.end());
            combined.insert(combined.end(), ciphertext.begin(), ciphertext.end());

            write_file_bytes(outputFile, combined);
        } else {
            std::vector<unsigned char> combined = read_file_bytes(inputFile);
            if (combined.size() < AES_IV_SIZE) {
                throw std::runtime_error("Too short input");
            }

            std::vector<unsigned char> iv(combined.begin(), combined.begin() + AES_IV_SIZE);
            std::vector<unsigned char> ciphertext(combined.begin() + AES_IV_SIZE, combined.end());

            std::vector<unsigned char> plaintext = aes_decrypt(ciphertext, key, iv);

            write_file_bytes(outputFile, plaintext);

    }

    } //End of File mode
    else if(mode == Mode::LIST) {
        if(inputFile.empty() || outputFile.empty()) {
            std::cerr << "Error: Input and output files are required for list mode\n";
            print_usage(argv[0]);
            return 1;
        }
        std::ifstream in(inputFile);
        if (!in) {
            throw std::runtime_error("Failed to open input file");
        }
        std::ofstream out(outputFile);
        if (!out) {
            throw std::runtime_error("Failed to open output file");
        }

        std::string line;
        while (std::getline(in, line)) {
            if (encrypt) {
                std::vector<unsigned char> iv;
                std::vector<unsigned char> plaintext(line.begin(), line.end());
                std::vector<unsigned char> ciphertext = aes_encrypt(plaintext, key, iv);

                std::vector<unsigned char> combined;
                combined.insert(combined.end(), iv.begin(), iv.end());
                combined.insert(combined.end(), ciphertext.begin(), ciphertext.end());

                out << base64_encode(combined) << "\n";
            } else {
                std::vector<unsigned char> combined = base64_decode(line);
                if (combined.size() < AES_IV_SIZE) {
                    throw std::runtime_error("Too short input in list");
                }

                std::vector<unsigned char> iv(combined.begin(), combined.begin() + AES_IV_SIZE);
                std::vector<unsigned char> ciphertext(combined.begin() + AES_IV_SIZE, combined.end());

                std::vector<unsigned char> plaintext = aes_decrypt(ciphertext, key, iv);

                out << std::string(plaintext.begin(), plaintext.end()) << "\n";
            }
        }
    } // End of List mode
} // End of try block
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }
    

    return 0;
}
