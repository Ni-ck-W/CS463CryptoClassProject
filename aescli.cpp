#include <iostream>

int main() {
    int choice;

    std::cout << "=== AES CLI Menu ===" << std::endl;
    std::cout << "1. Type text to encrypt/decrypt" << std::endl;
    std::cout << "2. Select a file to encrypt/decrypt" << std::endl;
    std::cout << "3. Select a file list to encrypt/decrypt" << std::endl;
    std::cout << "4. Exit" << std::endl;
    std::cout << "Enter your choice: ";
    std::cin >> choice;

    switch (choice) {
        case 1:
            std::cout << "Type text to encrypt/decrypt" << std::endl;
            break;
        case 2:
            std::cout << "Select a file to encrypt/decrypt" << std::endl;
            break;
        case 3:
            std::cout << "Select a file list to encrypt/decrypt" << std::endl;
            break;
        case 4:
            std::cout << "Exiting" << std::endl;
            break;
        default:
            std::cout << "Invalid choice" << std::endl;
            break;
    }

    return 0;
}
