#include <cstdio>

#include "version.h"

int main() {
    std::printf("nano-ngfw %s\n", nano::version());
    std::printf("scaffold only -- the pcap reader lands next.\n");
    return 0;
}
