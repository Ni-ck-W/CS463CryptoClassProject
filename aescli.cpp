#include <iostream>
#include <getopt.h>

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

int main(int argc, char *argv[]) {
    bool encrypt = false;
    bool decrypt = false;
    std::string mode_str;
    std::string text;
    std::string inputFile;
    std::string outputFile;
    std::string key;

    static struct option long_options[] = {
        {"encrypt", no_argument, 0, 'e'},
        {"decrypt", no_argument, 0, 'd'},
        {"mode", required_argument, 0, 'm'},
        {"text", required_argument, 0, 't'},
        {"input", required_argument, 0, 'i'},
        {"output", required_argument, 0, 'o'},
        {"key", required_argument, 0, 'k'},
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
                key = optarg;
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                return 0;
        }
    }

    return 0;
}
